import { randomBytes } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
try {
  await writeFile('.dev.vars', `VAULT_KEY="${randomBytes(32).toString('base64')}"\nSETUP_KEY="${randomBytes(32).toString('hex')}"\n`, {flag:'wx', mode:0o600});
  console.log('Created .dev.vars. Open that file locally to get your one-time setup key. Keep it private.');
} catch(e) {
  if(e.code==='EEXIST'){console.log('.dev.vars already exists; kept your existing keys.');}else throw e;
}
