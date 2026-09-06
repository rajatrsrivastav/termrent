import { readdirSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
for (const dir of ['bin', 'lib', 'public', 'scripts', 'test']) {
  for (const name of readdirSync(dir).filter(n => n.endsWith('.js'))) {
    execFileSync(process.execPath, ['--check', `${dir}/${name}`], { stdio: 'inherit' });
  }
}
const html = readFileSync('public/index.html', 'utf8');
if (!html.includes('src="/app.js"') || /https?:\/\//.test(html)) throw new Error('Invalid offline HTML assets');
await import('../lib/server.js');
await import('@noble/ciphers/aes.js');
console.log('JavaScript syntax, server imports, and offline assets checked (no compilation required).');
