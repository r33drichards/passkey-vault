# Git-sourced embedded engine / Cloudflare Workers verdict

Observed 2026-10-27: **blocked before deployment by native addon bundling**.

- Source: https://github.com/r33drichards/mcp-js/tree/e1f1d6552c5a2c2d3e7d39b069c1d07707dbc2f3/node
- Correct package subdirectory: `node/`. Root Git install is not a built distribution.
- Reused the successful `Build node tarball` job artifact from source run 40272173219, whose head SHA matches the pinned commit. This is Git-built code, not an npm registry engine download. No fresh native rebuild was performed.
- Source README documents Nix/Cargo V8 shared-library build, binding generation, npm TypeScript compilation, portability/packaging gates and npm pack. Generated bindings and ELF library are not committed.
- CI installed that validated artifact in Ubuntu 24.04 / Node 22. Engine.createStateless and callToolAsync('run_js', ...) executed console.log(6 * 7), returning {"output":"42"}.
- The same Engine import/API calls were placed in the attached Worker with nodejs_compat enabled.
- Wrangler 4.45.0 and 4.153.0 both failed deploy --dry-run: No loader is configured for ".node" files: @ubjs/node-linux-x64-gnu/uniffi-runtime-napi.linux-x64-gnu.node.
- This demonstrates that the current package cannot pass this normal Workers bundling path. Changing Git versus npm distribution does not remove its native Node-API / Linux ELF dependency. No claim of deployed engine execution is made.
- Deployment was skipped, so this failure is not a Cloudflare quota/auth failure. No Worker was created or production vault changed. Existing hello-world endpoint returned HTTP 200 during this run.
- No HTTP external-engine substitution, native-binary stubbing, paid Containers, or npm publication was used.

## Reproduce / evidence

Workflow: ../../.github/workflows/git-embed-proof.yml

Initial run: https://github.com/r33drichards/passkey-vault/actions/runs/40424575642

Current Wrangler confirmation: https://github.com/r33drichards/passkey-vault/actions/runs/40424693169

Each run retains `git-workers-embedding-evidence` for 14 days, including source-run/job provenance, full install lockfile, fixture, logs and artifact hash. Essential logs and fixture are also committed here permanently.

The deployment goal remains blocked. A Workers-compatible engine implementation/port would be a separate engineering task; retrying publishing or resetting quotas does not resolve this observed build error.
