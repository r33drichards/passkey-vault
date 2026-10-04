import { build } from 'esbuild';
import { copyFile } from 'node:fs/promises';
await build({ entryPoints: ['web/app.ts'], bundle: true, minify: true, format: 'esm', outfile: 'public/app.js', target: 'es2022' });
await Promise.all(['index.html', 'style.css'].map(f => copyFile(`web/${f}`, `public/${f}`)));
