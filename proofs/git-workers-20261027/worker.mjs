import { Engine } from '@wholelottahoopla/mcp-js-node';
export default { async fetch() {
  const engine = Engine.createStateless(64n, 1n);
  try {
    const result = JSON.parse(await engine.callToolAsync('run_js', JSON.stringify({code:'console.log(6 * 7)'}), undefined, undefined));
    return Response.json({commit:'e1f1d6552c5a2c2d3e7d39b069c1d07707dbc2f3', result});
  } finally { engine.close(); engine.uniffiDestroy(); }
}};
