import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join, dirname as pathDirname } from 'path';
import { fileURLToPath } from 'url';
import { globSync } from 'glob';
import { minify as jsMinify } from 'terser';
import { minify as htmlMinify } from 'html-minifier';
import pkg from '../package.json' with { type: 'json' };
import { gzipSync } from 'zlib';

const __filename = fileURLToPath(import.meta.url);
const __dirname = pathDirname(__filename);

const ASSET_PATH = join(__dirname, '../src/assets');
const DIST_PATH = join(__dirname, '../dist/');
// Path to the raw worker.js in the 'process' folder at the root of the repo
const PROCESS_WORKER_PATH = join(__dirname, '../process/worker.js'); 

const green = '\x1b[32m';
const red = '\x1b[31m';
const reset = '\x1b[0m';

const success = `${green}✔${reset}`;
const failure = `${red}✗${reset}`;

async function processHtmlPages() {
    const indexFiles = globSync('**/index.html', { cwd: ASSET_PATH });
    const result = {};

    for (const relativeIndexPath of indexFiles) {
        const dir = pathDirname(relativeIndexPath);
        const base = (file) => join(ASSET_PATH, dir, file);

        const indexHtml = readFileSync(base('index.html'), 'utf8');
        let html = indexHtml.replaceAll('__VERSION__', pkg.version);

        if (dir !== 'error') {
            const css = readFileSync(base('style.css'), 'utf8');

            const script = readFileSync(base('script.js'), 'utf8');
            const { code } = await jsMinify(script);

            html = html
                .replace('/* CSS_PLACEHOLDER */', css)
                .replace('/* JS_PLACEHOLDER */', code);
        }

        const minifiedHtml = htmlMinify(html, {
            collapseWhitespace: true,
            removeAttributeQuotes: true,
            minifyCSS: true
        });

        const compressed = gzipSync(minifiedHtml, { level: 9 });
        result[dir] = compressed.toString('base64');
    }

    console.log(`${success} Assets bundled successfully!`);
    return result;
}

async function buildSecureWorker() {
    const htmls = await processHtmlPages();
    const faviconBase64 = readFileSync('./src/assets/favicon.ico').toString('base64');

    // 1. Read the raw, uncompressed worker.js from the 'process' folder
    const rawWorkerCode = readFileSync(PROCESS_WORKER_PATH, 'utf8');
    console.log(`${success} Raw worker read successfully!`);

    // 2. Minify the worker code using Terser (applying obfuscation/minification)
    const { code: minifiedScript } = await jsMinify(rawWorkerCode, {
        module: true,
        output: {
            comments: false
        },
        compress: {
            dead_code: false,
            unused: false
        }
    });
    console.log(`${success} Worker minified successfully!`);

    // 3. Gzip and Base64 encode the minified worker code for SOURCE_CONTENT
    const base64Gzip = gzipSync(minifiedScript, { level: 9 }).toString("base64");

    const embededContents = {
        SOURCE_CONTENT: base64Gzip,
        PANEL_HTML_CONTENT: htmls['panel'],
        LOGIN_HTML_CONTENT: htmls['login'],
        ERROR_HTML_CONTENT: htmls['error'],
        PROXY_IP_HTML_CONTENT: htmls['proxy-ip'],
        ICON_CONTENT: faviconBase64
    };

    // 4. Combine the embedded contents and the minified script
    const worker = `Object.assign(globalThis, ${JSON.stringify(embededContents)});${minifiedScript}`;

    mkdirSync(DIST_PATH, { recursive: true });
    writeFileSync('./dist/worker.js', worker, 'utf8');

    console.log(`${success} Secure build created successfully!`);
    console.log(`${success} Done!`);
}

buildSecureWorker().catch(err => {
    console.error(`${failure} Secure build failed:`, err);
    process.exit(1);
});
