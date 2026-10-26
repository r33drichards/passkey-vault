import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
export default defineConfig({plugins:[cloudflareTest({wrangler:{configPath:'./wrangler.jsonc'},miniflare:{bindings:{APP_ORIGIN:'http://localhost:8787',PROVIDER_ORIGINS:'http://localhost:9322,https://www.npmjs.com,https://npmjs.com',VAULT_KEY:'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',SETUP_KEY:'test-only-setup-key-000000000000000000000000'}}})],test:{include:['tests/**/*.test.ts']}});
