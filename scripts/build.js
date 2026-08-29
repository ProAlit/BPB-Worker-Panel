import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join, dirname as pathDirname } from 'path';
import { fileURLToPath } from 'url';
import { build } from 'esbuild';
import { globSync } from 'glob';
import pkg from '../package.json' with { type: 'json' };

const __filename = fileURLToPath(import.meta.url);
const __dirname = pathDirname(__filename);

const ASSET_PATH = join(__dirname, '../src/assets');
const DIST_PATH = join(__dirname, '../dist/');

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

            // Inject raw CSS and JS without minification
            html = html
                .replace('/* CSS_PLACEHOLDER */', css)
                .replace('/* JS_PLACEHOLDER */', script);
        }

        // Store raw HTML string (no minification or gzip compression)
        result[dir] = html;
    }

    console.log(`${success} Assets bundled successfully!`);
    return result;
}

async function buildWorker() {
    const htmls = await processHtmlPages();
    
    // Keep favicon as base64 since it is a binary file
    const faviconBase64 = readFileSync('./src/assets/favicon.ico').toString('base64');

    const code = await build({
        entryPoints: [join(__dirname, '../src/worker.ts')],
        bundle: true,
        format: 'esm',
        write: false,
        external: [
            'cloudflare:sockets',
            'node:crypto'
        ],
        platform: 'browser',
        target: 'esnext',
        loader: { '.ts': 'ts' },
        define: { VERSION: `"${pkg.version}"` }
    });

    console.log(`${success} Worker built successfully!`);

    // Raw ESBuild output (no terser minification)
    const script = code.outputFiles[0].text;

    console.log(`${success} Worker processed successfully!`);

    const embededContents = {
        // SOURCE_CONTENT removed as we no longer compress/gzip the worker payload
        PANEL_HTML_CONTENT: htmls['panel'],
        LOGIN_HTML_CONTENT: htmls['login'],
        ERROR_HTML_CONTENT: htmls['error'],
        PROXY_IP_HTML_CONTENT: htmls['proxy-ip'],
        ICON_CONTENT: faviconBase64
    };

    // Assign raw, uncompressed strings to globalThis
    const worker = `Object.assign(globalThis, ${JSON.stringify(embededContents)});\n\n${script}`;

    mkdirSync(DIST_PATH, { recursive: true });
    writeFileSync('./dist/worker.js', worker, 'utf8');

    console.log(`${success} Done!`);
}

buildWorker().catch(err => {
    console.error(`${failure} Build failed:`, err);
    process.exit(1);
});
