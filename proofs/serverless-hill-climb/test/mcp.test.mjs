import {test} from 'node:test';
import assert from 'node:assert/strict';
import {NativeMcp} from '../src/mcp.mjs';
import {OwnerAuthority} from '../src/worker.mjs';
const lease={url:'https://test.modal.host/mcp',token:'CONNECT_TEST_SECRET',sandbox:'sb-test'};
function sse(id,result){return new Response('data: \nid: 0\n\ndata: '+JSON.stringify({jsonrpc:'2.0',id,result})+'\n\n',{headers:{'Content-Type':'text/event-stream','Mcp-Session-Id':'session-1'}});}
test('native initialization, session header and repeated tools use same direct endpoint',async()=>{
 let calls=0;const client=new NativeMcp(async(url,opts)=>{
  assert.equal(url,lease.url);assert.equal(opts.headers.Authorization,'Bearer '+lease.token);assert.equal(opts.redirect,'manual');calls++;
  const p=JSON.parse(opts.body);
  if(p.method==='initialize')return sse(p.id,{protocolVersion:'2024-11-05'});
  assert.equal(opts.headers['Mcp-Session-Id'],'session-1');
  if(p.method==='notifications/initialized')return new Response(null,{status:202});
  assert.equal(p.method,'tools/call');return sse(p.id,{content:[{type:'text',text:'42'}],isError:false});
 },lease);
 await client.initialize();assert.equal((await client.run('console.log(42)')).isError,false);await client.run('console.log(43)');assert.equal(calls,4);
});
test('split CRLF event framing and JSON fallback',async()=>{
 const bytes=new TextEncoder().encode('data: {"jsonrpc":"2.0","id":1,"result":{"content":[]}}\r\n\r\n');let i=0;
 const client=new NativeMcp(async()=>new Response(new ReadableStream({pull(c){if(i===bytes.length)c.close();else c.enqueue(bytes.slice(i,++i));}}),{headers:{'Content-Type':'text/event-stream'}}),lease);
 assert.deepEqual(await client.run(''),{content:[]});
 const json=new NativeMcp(async()=>Response.json({jsonrpc:'2.0',id:1,result:{content:[]}}),lease);assert.deepEqual(await json.run(''),{content:[]});
});
test('HTTP errors and protocol errors never retry',async()=>{
 let calls=0;const c=new NativeMcp(async()=>{calls++;return new Response(null,{status:503});},lease);
 await assert.rejects(c.run(''));assert.equal(calls,1);
 const e=new NativeMcp(async()=>Response.json({jsonrpc:'2.0',id:1,error:{message:'secret'}}),lease);await assert.rejects(e.run(''),/mcp-protocol-error/);
});
test('output budget and wrong IDs fail closed',async()=>{
 const huge=new NativeMcp(async()=>new Response('x'.repeat(65537)),lease);await assert.rejects(huge.run(''),/output-limit/);
 const wrong=new NativeMcp(async()=>sse(99,{content:[]}),lease);await assert.rejects(wrong.run(''),/missing-result/);
 assert.throws(()=>new NativeMcp(()=>{}, {...lease,url:'https://attacker.test/mcp'}));
});
test('release records termination only after controller confirmation',async()=>{
 const a=new OwnerAuthority({storage:{}},{}),run={lease:{id:'a'.repeat(64)},tools:[{}]};
 a.lifecycle=async(op,body)=>{assert.equal(op,'release');return {lease:body.lease,terminated:true};};
 assert.equal(await a.releaseLease(run),true);assert.equal(run.tools[0].terminated,true);
 a.lifecycle=async()=>{throw Error('network');};assert.equal(await a.releaseLease(run),false);assert.equal(run.lease.status,'cleanup-unverified');
});
