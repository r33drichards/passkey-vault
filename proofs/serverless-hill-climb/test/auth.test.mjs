import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPair, exportJWK, SignJWT} from 'jose';
import worker, {OwnerAuthority} from '../src/worker.mjs';

const ORIGIN='https://durable-pi-modal.example';
class Storage {
  data=new Map();
  async setAlarm(v){this.alarm=v;}
  async deleteAlarm(){delete this.alarm;}
  async get(k){return this.data.get(k);}
  async put(k,v){this.data.set(k,structuredClone(v));}
  async delete(k){for(const x of Array.isArray(k)?k:[k]) this.data.delete(x);}
}
function fixture(){
  const storage=new Storage();
  const env={PUBLIC_ORIGIN:ORIGIN,GITHUB_OWNER_ID:'57335981',GITHUB_OWNER_LOGIN:'r33drichards',VAULT_KEY:Buffer.alloc(32,7).toString('base64')};
  const auth=new OwnerAuthority({storage},env);
  auth.fetcher=async()=>{throw Error('unexpected network');};
  return {auth,storage,env};
}
const req=(path,options={})=>new Request(ORIGIN+path,options);
const cookiePair=s=>s.split(';')[0];
async function session(auth){
  const s={owner:'57335981',sid:'test-session',csrf:'test-csrf',epoch:0};
  return {s,cookie:cookiePair(await auth.setCookie('session',s,3600))};
}
const post=(path,cookie,values={},origin=ORIGIN)=>req(path,{method:'POST',headers:{Cookie:cookie,Origin:origin,'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf:'test-csrf',...values})});
async function start(auth){
  const current=await session(auth);
  assert.equal((await auth.fetch(post('/admin/chatgpt/start',current.cookie))).status,303);
  return {...current,pending:await auth.read('chatgpt-pending')};
}
function callback(p){return `http://127.0.0.1:1455/auth/callback?state=${p.state}&client_id=oaiapp_test&code=oneusecode`;}
const grant={access_token:'ACCESS_SECRET',refresh_token:'REFRESH_SECRET',scope:'openid chatgpt.tokens.use.direct',expires_in:3600};

test('public routing never exposes internal credential methods or webhook',async()=>{
  const {env}=fixture();env.AUTH={get(){throw Error('must not reach DO');}};
  for(const p of ['/internal/credential','/withModelCredential']) assert.equal((await worker.fetch(req(p),env)).status,404);
  assert.equal((await worker.fetch(req('/health'),env)).status,200);
  assert.equal((await worker.fetch(new Request('https://evil.test/admin'),env)).status,421);
});
test('bootstrap manifest has no permissions and correct callback; sealed cookie',async()=>{
  const {auth}=fixture(); const r=await auth.fetch(req('/admin')); const html=await r.text();
  assert.equal(r.status,200); assert.match(html,/Set up with GitHub/);
  assert.match(html,/default_permissions&amp;quot;|default_permissions&quot;/);
  assert.match(html,/r33drichards/); assert.match(r.headers.get('set-cookie'),/Secure; HttpOnly; SameSite=Lax/);
  assert.equal(r.headers.get('Cache-Control'),'no-store, private');
});
test('wrong GitHub app owner cannot claim setup',async()=>{
  const {auth}=fixture();
  const c=cookiePair(await auth.setCookie('flow',{purpose:'manifest',state:'state'},600));
  auth.fetcher=async()=>Response.json({owner:{id:999},id:1,client_id:'x',client_secret:'secret'});
  const r=await auth.fetch(req('/setup/callback?state=state&code=abcdefghijklmn',{headers:{Cookie:c}}));
  assert.equal(r.status,403);assert.equal(await auth.read('github-app'),undefined);
});
test('provider requests use Workers-compatible manual redirects and never follow them',async()=>{
  const {auth}=fixture(); let calls=0;
  auth.fetcher=async(url,options)=>{
    calls++; assert.equal(options.redirect,'manual');
    return new Response(null,{status:302,headers:{Location:'https://untrusted.example'}});
  };
  await assert.rejects(auth.json('https://api.github.com/user',{headers:{Authorization:'Bearer TEST_ONLY'}}),e=>e.safe && e.status===502);
  assert.equal(calls,1);
});
test('owner manifest conversion stores encrypted app, encrypts PEM; replay denied',async()=>{
  const {auth,storage}=fixture();
  const c=cookiePair(await auth.setCookie('flow',{purpose:'manifest',state:'state'},600));
  let calls=0; auth.fetcher=async()=>{calls++;return Response.json({owner:{id:57335981},id:1,client_id:'id',client_secret:'APP_SECRET',pem:'PRIVATE_KEY',webhook_secret:'HOOK_SECRET',slug:'hill-test'});};
  const request=()=>req('/setup/callback?state=state&code=abcdefghijklmn',{headers:{Cookie:c}});
  assert.equal((await auth.fetch(request())).status,303);
  assert.equal((await auth.read('github-app')).clientSecret,'APP_SECRET');
  assert.doesNotMatch(JSON.stringify([...storage.data]),/APP_SECRET|PRIVATE_KEY/);
  assert.equal((await auth.fetch(request())).status,409);assert.equal(calls,1);
});
test('GitHub callback checks numeric identity, not username',async()=>{
  const {auth}=fixture();await auth.save('github-app',{clientId:'app',clientSecret:'secret'});
  const c=cookiePair(await auth.setCookie('flow',{purpose:'github',state:'state',verifier:'verifier'},600));
  auth.fetcher=async url=>url.endsWith('/user')?Response.json({id:999,login:'r33drichards'}):Response.json({access_token:'secret'});
  assert.equal((await auth.fetch(req('/auth/github/callback?state=state&code=one',{headers:{Cookie:c}}))).status,403);
});
test('correct GitHub identity gets owner session, wrong state and replay rejected',async()=>{
  const {auth}=fixture();await auth.save('github-app',{clientId:'app',clientSecret:'secret'});
  const c=cookiePair(await auth.setCookie('flow',{purpose:'github',state:'state',verifier:'verifier'},600));
  let calls=0;auth.fetcher=async url=>{calls++;return url.endsWith('/user')?Response.json({id:57335981,login:'renamed-owner'}):Response.json({access_token:'secret'});};
  assert.equal((await auth.fetch(req('/auth/github/callback?state=bad&code=one',{headers:{Cookie:c}}))).status,400);assert.equal(calls,0);
  const r=await auth.fetch(req('/auth/github/callback?state=state&code=one',{headers:{Cookie:c}}));assert.equal(r.status,303);
  const set=r.headers.getSetCookie().find(x=>x.startsWith('__Host-session='));
  assert.equal((await auth.session(req('/admin',{headers:{Cookie:cookiePair(set)}}))).owner,'57335981');
  assert.equal((await auth.fetch(req('/auth/github/callback?state=state&code=one',{headers:{Cookie:c}}))).status,409);assert.equal(calls,2);
});
test('all ChatGPT routes require owner session; CSRF and cross-origin rejected',async()=>{
  const {auth}=fixture();const {cookie}=await session(auth);
  assert.equal((await auth.fetch(req('/admin/chatgpt'))).status,401);
  assert.equal((await auth.fetch(post('/admin/chatgpt/start',''))).status,401);
  assert.equal((await auth.fetch(post('/admin/chatgpt/start',cookie,{},'https://evil.test'))).status,403);
  assert.equal((await auth.fetch(post('/admin/chatgpt/start',cookie,{csrf:'wrong'}))).status,403);
  assert.equal((await auth.fetch(req('/admin/chatgpt/start',{headers:{Cookie:cookie}}))).status,405);
});
test('cookie tamper, purpose confusion, expiry and logout invalidate access',async()=>{
  const {auth}=fixture();const {s,cookie}=await session(auth);
  assert.equal(await auth.session(req('/admin',{headers:{Cookie:cookie.slice(0,-2)+'XX'}})),undefined);
  const wrong=cookiePair(await auth.setCookie('flow',s,3600)).replace('__Host-flow=','__Host-session=');
  assert.equal(await auth.session(req('/admin',{headers:{Cookie:wrong}})),undefined);
  const expired=cookiePair(await auth.setCookie('session',s,-1));
  assert.equal(await auth.session(req('/admin',{headers:{Cookie:expired}})),undefined);
  await auth.fetch(post('/admin/logout',cookie));assert.equal(await auth.session(req('/admin',{headers:{Cookie:cookie}})),undefined);
});
test('ChatGPT flow has PKCE, stable host; invalid callback does not dispatch',async()=>{
  const {auth}=fixture();const {cookie,pending}=await start(auth);
  const r=await auth.fetch(req('/admin/chatgpt',{headers:{Cookie:cookie}}));const html=await r.text();
  assert.match(html,/code_challenge_method=S256/);assert.doesNotMatch(html,new RegExp(pending.verifier));
  assert.equal((await auth.fetch(post('/admin/chatgpt/complete',cookie,{callback:callback(pending).replace(pending.state,'wrong')}))).status,400);
  assert.equal((await auth.read('chatgpt-pending')).status,'pending');
  await auth.fetch(post('/admin/chatgpt/start',cookie));assert.equal((await auth.read('chatgpt-pending')).host,pending.host);
});
test('ChatGPT signature/audience/nonce verified; encrypted credentials survive instance recreation',async()=>{
  const {auth,storage,env}=fixture();const {cookie,pending}=await start(auth);
  const keys=await generateKeyPair('RS256');const jwk=await exportJWK(keys.publicKey);jwk.kid='key';
  const jwt=await new SignJWT({nonce:pending.nonce,email:'owner@example.test'}).setProtectedHeader({alg:'RS256',kid:'key'}).setIssuer('https://auth.openai.com').setAudience('oaiapp_test').setSubject('subject').setIssuedAt().setExpirationTime('5m').sign(keys.privateKey);
  auth.fetcher=async url=>url.endsWith('jwks.json')?Response.json({keys:[jwk]}):Response.json({...grant,id_token:jwt});
  assert.equal((await auth.fetch(post('/admin/chatgpt/complete',cookie,{callback:callback(pending)}))).status,303);
  assert.doesNotMatch(JSON.stringify([...storage.data]),/ACCESS_SECRET|REFRESH_SECRET|owner@example/);
  const restored=new OwnerAuthority({storage},env);
  assert.equal((await restored.read('chatgpt')).credential.access,'ACCESS_SECRET');
  assert.equal(await restored.withModelCredential(c=>c.clientId),'oaiapp_test');
  assert.equal((await auth.fetch(post('/admin/chatgpt/complete',cookie,{callback:callback(pending)}))).status,409);
});
test('invalid ID-token claims never install credentials',async()=>{
  const {auth}=fixture();const keys=await generateKeyPair('RS256');const jwk=await exportJWK(keys.publicKey);jwk.kid='key';
  auth.fetcher=async()=>Response.json({keys:[jwk]});
  for(const patch of [{nonce:'bad'},{aud:'bad'},{iss:'https://evil.test'},{exp:1}]) {
    const claims={sub:'owner',iss:'https://auth.openai.com',aud:'oaiapp_test',iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+300,nonce:'nonce',...patch};
    const token=await new SignJWT(claims).setProtectedHeader({alg:'RS256',kid:'key'}).sign(keys.privateKey);
    await assert.rejects(auth.verifyIdentity(token,'oaiapp_test','nonce'));
  }
  assert.equal(await auth.read('chatgpt'),undefined);
});
test('missing plan scope, stale browser session, expired pending flow rejected',async()=>{
  const {auth}=fixture();const {cookie,pending}=await start(auth);
  assert.throws(()=>auth.credential({...grant,scope:'openid'},'client'));
  await auth.save('chatgpt-pending',{...pending,sid:'other'});
  assert.equal((await auth.fetch(req('/admin/chatgpt',{headers:{Cookie:cookie}}))).status,409);
  await auth.save('chatgpt-pending',{...pending,expires:0});
  assert.equal((await auth.fetch(req('/admin/chatgpt',{headers:{Cookie:cookie}}))).status,409);
});
test('code exchange uncertainty is not replayed; previous credential retained',async()=>{
  const {auth}=fixture();const {cookie,pending}=await start(auth);let calls=0;
  await auth.save('chatgpt',{status:'ready',credential:{access:'old'}});
  auth.fetcher=async()=>{calls++;throw Error('network timeout');};
  assert.equal((await auth.fetch(post('/admin/chatgpt/complete',cookie,{callback:callback(pending)}))).status,500);
  assert.equal((await auth.fetch(post('/admin/chatgpt/complete',cookie,{callback:callback(pending)}))).status,409);
  assert.equal(calls,1);assert.equal((await auth.read('chatgpt')).credential.access,'old');
});
test('refresh serialized and persisted once; restart after reserved refresh requires reconnect',async()=>{
  const {auth,storage,env}=fixture();
  await auth.save('chatgpt',{status:'ready',identity:{sub:'owner'},credential:{access:'expired',refresh:'old-refresh',expires:0,clientId:'client'}});
  let calls=0;auth.fetcher=async()=>{calls++;return Response.json(grant);};
  const results=await Promise.all([auth.withModelCredential(c=>c.access),auth.withModelCredential(c=>c.access)]);
  assert.deepEqual(results,['ACCESS_SECRET','ACCESS_SECRET']);assert.equal(calls,1);
  const value=await auth.read('chatgpt');value.status='refreshing';await auth.save('chatgpt',value);
  const restarted=new OwnerAuthority({storage},env);
  await assert.rejects(restarted.withModelCredential(()=>{}),/Reconnect/);
});
test('disconnect deletes model credentials; public response never exposes them',async()=>{
  const {auth}=fixture();const {cookie}=await session(auth);
  await auth.save('github-app',{clientId:'app',clientSecret:'secret'});
  await auth.save('chatgpt',{status:'ready',identity:{sub:'owner'},credential:{access:'ACCESS_SECRET',refresh:'REFRESH_SECRET'}});
  const r=await auth.fetch(req('/admin',{headers:{Cookie:cookie}}));assert.doesNotMatch(await r.text(),/ACCESS_SECRET|REFRESH_SECRET/);
  assert.equal((await auth.fetch(post('/admin/chatgpt/disconnect',cookie))).status,200);
  assert.equal(await auth.read('chatgpt'),undefined);
});

test('inference verification requires independent CI capability and exposes no credential',async()=>{
  const {auth,env,storage}=fixture(); env.VERIFY_KEY='test-only-capability';
  const denied=await auth.fetch(req('/ops/verify',{method:'POST'}));
  assert.equal(denied.status,401);
  await auth.save('chatgpt',{status:'ready',credential:{access:'PRIVATE_ACCESS',refresh:'PRIVATE_REFRESH',expires:Date.now()+3600000}});
  let calls=0;
  auth.fetcher=async(url,opts)=>{calls++;assert.equal(url,'https://api.openai.com/v1/models');assert.equal(opts.headers.Authorization,'Bearer PRIVATE_ACCESS');return new Response('provider private body',{status:403});};
  const run=()=>auth.fetch(req('/ops/verify',{method:'POST',headers:{Authorization:'Bearer test-only-capability'}}));
  const result=await (await run()).json();
  assert.equal(result.status,'blocked');assert.equal(result.httpStatus,403);
  assert.deepEqual(await (await run()).json(),result);assert.equal(calls,1);
  assert.doesNotMatch(JSON.stringify(result),/PRIVATE|provider private/);
  assert.doesNotMatch(storage.data.get('inference-proof-v2'),/blocked|catalog/);
});


test('webhook owner capability, timestamp, durable deduplication and collision rejection',async()=>{
  const {auth,env,storage}=fixture();env.WEBHOOK_KEY='hook-secret';
  const body={id:'event-1',session:'proof-a',prompt:'test',timestamp:Date.now()};
  const send=(b,key='hook-secret')=>auth.fetch(req('/webhook',{method:'POST',headers:{Authorization:'Bearer '+key},body:JSON.stringify(b)}));
  assert.equal((await send(body,'wrong')).status,401);
  assert.equal((await send({...body,timestamp:0})).status,400);
  assert.equal((await send(body)).status,202);
  assert.equal((await (await send(body)).json()).duplicate,true);
  assert.equal((await send({...body,prompt:'different'})).status,409);
  assert.equal((await send({...body,id:'event-2'})).status,409);
  assert.equal(storage.data.get('run-count'),1);
  assert.equal((await auth.read('run:event-1')).status,'queued');
  assert.ok(storage.alarm);
  assert.doesNotMatch(storage.data.get('run:event-1'),/test|proof-a/);
});
test('alarm never replays uncertain in-flight execution after restart',async()=>{
  const {auth,storage}=fixture();
  await storage.put('active-run','uncertain');
  await auth.save('run:uncertain',{id:'uncertain',status:'running'});
  await auth.alarm();
  assert.equal((await auth.read('run:uncertain')).status,'interrupted');
  assert.equal(await storage.get('active-run'),undefined);
});
