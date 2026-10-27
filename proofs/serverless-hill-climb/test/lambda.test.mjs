import {test} from 'node:test';
import assert from 'node:assert/strict';
import {LambdaMcp,LAMBDA_ENDPOINT,TOKEN_ENDPOINT} from '../src/mcp.mjs';
const session='pi-'+ 'a'.repeat(64);
test('Lambda uses bounded OAuth, inline execution, stable session and refresh without initialization',async()=>{
 let now=0,tokens=0,tools=0;
 const client=new LambdaMcp(async(url,opts)=>{
  assert.equal(opts.redirect,'manual');
  if(url===TOKEN_ENDPOINT){tokens++;assert.equal(new URLSearchParams(opts.body).get('grant_type'),'client_credentials');return Response.json({access_token:'test-'+tokens,token_type:'Bearer',expires_in:300});}
  assert.equal(url,LAMBDA_ENDPOINT);tools++;
  assert.equal(opts.headers.Authorization,'Bearer test-'+tokens);
  assert.equal(opts.headers['X-MCP-Session-Id'],session);
  const p=JSON.parse(opts.body);assert.equal(p.method,'tools/call');
  assert.equal(p.params.arguments.wait,true);assert.equal(p.params.arguments.execution_timeout_secs,15);assert.equal(p.params.arguments.fs,undefined);
  return Response.json({jsonrpc:'2.0',id:p.id,result:{content:[{type:'text',text:'{"status":"completed","output":"42"}'}]}});
 },'test-secret',session,()=>now);
 await client.initialize();await client.run('console.log(42)');await client.run('console.log(43)');assert.equal(tokens,1);
 now=271000;await client.run('console.log(44)');assert.equal(tokens,2);assert.equal(tools,3);
});
test('Lambda does not replay uncertain calls or refresh-and-retry 401',async()=>{
 for(const failure of ['network',401]){
  let calls=0;
  const client=new LambdaMcp(async(url)=>{
   if(url===TOKEN_ENDPOINT)return Response.json({access_token:'test',token_type:'Bearer',expires_in:300});
   calls++;if(failure==='network')throw Error('network');return new Response(null,{status:401});
  },'secret',session);
  await assert.rejects(client.run('sideEffect()'));assert.equal(calls,1);
 }
});
test('Lambda rejects malformed credentials, session and token response before tool dispatch',async()=>{
 assert.throws(()=>new LambdaMcp(()=>{},'',session));assert.throws(()=>new LambdaMcp(()=>{},'secret','../bad'));
 let calls=0;const client=new LambdaMcp(async()=>{calls++;return Response.json({access_token:'x',token_type:'Bearer',expires_in:10});},'secret',session);
 await assert.rejects(client.run(''),/oauth-invalid-response/);assert.equal(calls,1);
});

test('fixed Lambda probe is routed but rejects unauthenticated callers',async()=>{
 const {default:worker,OwnerAuthority}=await import('../src/worker.mjs');
 const origin='https://unit.example';
 const authority=new OwnerAuthority({storage:{}},{PUBLIC_ORIGIN:origin,VERIFY_KEY:'private'});
 const env={PUBLIC_ORIGIN:origin,AUTH:{idFromName:()=> 'owner',get:()=>authority}};
 const response=await worker.fetch(new Request(origin+'/ops/lambda-probe',{method:'POST'}),env);
 assert.equal(response.status,401);
});

test('authenticated probe uses the real Worker hash and OAuth transport',async()=>{
 const {default:worker,OwnerAuthority}=await import('../src/worker.mjs');
 const origin='https://unit.example';
 const env={PUBLIC_ORIGIN:origin,VERIFY_KEY:'private',PI_TOOL_TRANSPORT:'lambda',LAMBDA_CLIENT_SECRET:'secret'};
 const authority=new OwnerAuthority({storage:{}},env);authority.read=async()=>undefined;
 let requests=0;
 authority.fetcher=async(url,opts)=>{
  if(url===TOKEN_ENDPOINT)return Response.json({access_token:'token',token_type:'Bearer',expires_in:300});
  requests++;assert.equal(url,LAMBDA_ENDPOINT);
  assert.match(opts.headers['X-MCP-Session-Id'],/^pi-[a-f0-9]{64}$/);
  const p=JSON.parse(opts.body);assert.equal(p.params.arguments.fs,undefined);
  return Response.json({jsonrpc:'2.0',id:p.id,result:{content:[{type:'text',text:JSON.stringify({status:'completed',output:'pi-lambda-connected'})}]}});
 };
 env.AUTH={idFromName:()=> 'owner',get:()=>authority};
 const response=await worker.fetch(new Request(origin+'/ops/lambda-probe',{method:'POST',headers:{Authorization:'Bearer private'}}),env);
 assert.equal(response.status,200);assert.equal((await response.json()).status,'passed');assert.equal(requests,1);
});
