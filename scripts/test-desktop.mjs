// Run only against disposable localhost vault/browser profiles. Never production.
// Prerequisites: wrangler dev on 8787, Chromium CDP on 9333, unpacked extension
// pinned to localhost:8787, disposable test-ssh-key in process.cwd().
import http from 'node:http';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { verifyRegistrationResponse, verifyAuthenticationResponse } from '@simplewebauthn/server';
const ROOT=process.cwd(),vault='http://localhost:8787',site='http://localhost:9322';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const server=http.createServer((_req,res)=>{res.setHeader('Content-Type','text/html');res.end('<!doctype html><title>Disposable provider test</title><h1>Passkey Vault integration test</h1><p>Test-only localhost credentials.</p>');});
await new Promise(r=>server.listen(9322,'127.0.0.1',r));
const unallowedServer=http.createServer(server.listeners('request')[0]);await new Promise(r=>unallowedServer.listen(9323,'127.0.0.1',r));
const info=await fetch('http://127.0.0.1:9333/json/version').then(r=>r.json());
const ws=new WebSocket(info.webSocketDebuggerUrl);await new Promise(r=>ws.onopen=r);
let id=0;const pending=new Map(),targets=[];
ws.onmessage=e=>{const m=JSON.parse(e.data);if(m.id){const p=pending.get(m.id);pending.delete(m.id);m.error?p.reject(Error(JSON.stringify(m.error))):p.resolve(m.result);}};
const call=(method,params={},sessionId)=>new Promise((resolve,reject)=>{const n=++id;pending.set(n,{resolve,reject});ws.send(JSON.stringify({id:n,method,params,...(sessionId?{sessionId}:{})}));});
async function evaluate(sessionId,expression){const r=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true,userGesture:true},sessionId);if(r.exceptionDetails)throw Error(r.exceptionDetails.text+' '+JSON.stringify(r.exceptionDetails.exception));return r.result.value;}
async function waitFor(fn,label){for(let n=0;n<100;n++){const r=await fn();if(r)return r;await sleep(100);}throw Error('Timeout: '+label);}
async function tab(url){const {targetId}=await call('Target.createTarget',{url});targets.push(targetId);const {sessionId}=await call('Target.attachToTarget',{targetId,flatten:true});await waitFor(()=>evaluate(sessionId,'document.readyState === "complete"'),'page ready');return {targetId,sessionId};}
let ext;
try {
 // Disable the old transport probe if it remains installed in this isolated profile.
 const {targetInfos}=await call('Target.getTargets');
 for(const t of targetInfos.filter(t=>t.type==='page'&&t.url.startsWith('chrome-extension://')&&t.url.endsWith('/popup.html'))){const {sessionId}=await call('Target.attachToTarget',{targetId:t.targetId,flatten:true});await evaluate(sessionId,'chrome.webAuthenticationProxy.detach().catch(()=>{})');}
 const {id:extensionId}=await call('Extensions.loadUnpacked',{path:ROOT+'/extension'});
 ext=await tab(`chrome-extension://${extensionId}/popup.html`);
 const owner=await tab(vault);
 const status=await evaluate(owner.sessionId,'fetch("/api/status").then(r=>r.json())');
 // Bootstrap a TEST vault only. The native virtual authenticator never touches npm.
 if(!status.initialized){
  await call('WebAuthn.enable',{},owner.sessionId);
  const {authenticatorId}=await call('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}},owner.sessionId);
  const setup=await evaluate(owner.sessionId,`(async()=>{const post=(p,b)=>fetch('/api/'+p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}).then(async r=>({status:r.status,body:await r.json()}));const o=await post('setup/options',{setupKey:'desktop-test-setup-key-000000000000000000000'});const c=await navigator.credentials.create({publicKey:PublicKeyCredential.parseCreationOptionsFromJSON(o.body.options)});return post('setup/verify',{response:c.toJSON()});})()`);
  assert.equal(setup.status,200,JSON.stringify(setup));
  await call('WebAuthn.removeVirtualAuthenticator',{authenticatorId},owner.sessionId);await call('WebAuthn.disable',{},owner.sessionId);
 }
 let signed=await evaluate(owner.sessionId,'fetch("/api/status").then(r=>r.json()).then(v=>v.signedIn)');
 const pub=readFileSync(ROOT+'/test-ssh-key.pub','utf8');
 function sign(challenge){const p=ROOT+'/test-approval.txt';writeFileSync(p,challenge,{mode:0o600});rmSync(p+'.sig',{force:true});execFileSync('ssh-keygen',['-Y','sign','-f',ROOT+'/test-ssh-key','-n','passkey-vault',p],{stdio:'ignore'});const result=readFileSync(p+'.sig','utf8');rmSync(p);rmSync(p+'.sig');return result;}
 if(!signed){
  const c=await evaluate(owner.sessionId,`fetch('/api/recovery/options',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({publicKey:${JSON.stringify(pub)}})}).then(r=>r.json())`);
  assert.ok(c.challenge,'Test vault must have its disposable recovery key');
  const ok=await evaluate(owner.sessionId,`fetch('/api/recovery/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({signature:${JSON.stringify(sign(c.challenge))}})}).then(r=>r.status)`);assert.equal(ok,200);
 }
 const registered=await evaluate(owner.sessionId,'fetch("/api/ssh-keys").then(r=>r.json()).then(v=>v.keys?.some(k=>k.name==="Disposable test key"))');
 if(!registered){const added=await evaluate(owner.sessionId,`fetch('/api/ssh-keys/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({publicKey:${JSON.stringify(pub)},name:'Disposable test key'})}).then(r=>r.status)`);assert.ok([200,409].includes(added));}
 assert.deepEqual(await evaluate(ext.sessionId,'chrome.runtime.sendMessage({action:"attach"})'),{ok:true});
 console.log('PASS isolated vault bootstrap and provider attachment');
 const rp=await tab(site);
 async function request(kind,options){
  await call('Page.bringToFront',{},rp.sessionId);
  await evaluate(rp.sessionId,`window.testResult=null; window.testAbort=new AbortController(); navigator.credentials.${kind}({signal:window.testAbort.signal,publicKey:PublicKeyCredential.${kind==='create'?'parseCreationOptionsFromJSON':'parseRequestOptionsFromJSON'}(${JSON.stringify(options)})}).then(c=>{window.testResult={credential:c.toJSON()}},e=>{window.testResult={error:e.name+': '+e.message}});undefined`);
  const target=await waitFor(async()=>{const r=await call('Target.getTargets');return r.targetInfos.find(t=>t.url===vault+'/provider'&&!targets.includes(t.targetId));},'approval tab');targets.push(target.targetId);
  const {sessionId}=await call('Target.attachToTarget',{targetId:target.targetId,flatten:true});
  await waitFor(()=>evaluate(sessionId,'document.readyState === "complete"'),'approval loaded');
  await evaluate(sessionId,'document.getElementById("load").click()');
  await waitFor(async()=>{const v=await evaluate(sessionId,'({url:location.href,status:document.getElementById("status")?.textContent,count:document.getElementById("key")?.options.length})');if(v.count)return true;if(v.status && !v.status.includes('Waiting') && !v.status.includes('Review'))throw Error('Approval UI: '+JSON.stringify(v));return false;},'SSH keys loaded');
  return sessionId;
 }
 async function approve(sessionId){
  await evaluate(sessionId,'document.getElementById("prepare").requestSubmit()');
  const challenge=await waitFor(()=>evaluate(sessionId,'document.getElementById("challenge").textContent'),'challenge');
  await call('Emulation.setDeviceMetricsOverride',{width:1100,height:1000,deviceScaleFactor:1,mobile:false},sessionId);
  const screenshot=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:true},sessionId);writeFileSync(ROOT+'/approval-test.png',Buffer.from(screenshot.data,'base64'));
  await evaluate(sessionId,`document.getElementById('signature').value=${JSON.stringify(sign(challenge))};document.getElementById('complete').requestSubmit()`);
  const result=await waitFor(async()=>{const r=await evaluate(rp.sessionId,'window.testResult');if(r)return r;const status=await evaluate(sessionId,'document.getElementById("status").textContent');if(!status.startsWith('Sign this')&&!status.startsWith('Credential operation'))throw Error('Completion UI: '+status);return false;},'browser result');
  assert.ok(result.credential,JSON.stringify(result));return result.credential;
 }
 const challenge=Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');
 const options={challenge,rp:{id:'localhost',name:'Test RP'},user:{id:'dGVzdC11c2Vy',name:'desktop-test',displayName:'Desktop test'},pubKeyCredParams:[{type:'public-key',alg:-7}],authenticatorSelection:{residentKey:'required',userVerification:'discouraged'},attestation:'none',timeout:120000};
 const reg=await approve(await request('create',options));
 const verified=await verifyRegistrationResponse({response:reg,expectedChallenge:challenge,expectedOrigin:site,expectedRPID:'localhost',requireUserVerification:false});assert.ok(verified.verified);assert.equal(verified.registrationInfo.userVerified,false);
 console.log('PASS browser registration and independent verifier (UP=true, UV=false)');
 const get={challenge:Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url'),rpId:'localhost',userVerification:'discouraged',allowCredentials:[{id:reg.id,type:'public-key'}],timeout:120000};
 const auth=await approve(await request('get',get));
 assert.ok((await verifyAuthenticationResponse({response:auth,expectedChallenge:get.challenge,expectedOrigin:site,expectedRPID:'localhost',credential:verified.registrationInfo.credential,requireUserVerification:false})).verified);
 console.log('PASS browser assertion and independent signature verification');
 const cancel=await request('get',get);await evaluate(cancel,'document.getElementById("cancel").click()');
 const canceled=await waitFor(()=>evaluate(rp.sessionId,'window.testResult'),'cancel');assert.match(canceled.error,/NotAllowedError/);console.log('PASS cancel rejects browser request');
 const required=await request('get',{...get,userVerification:'required'});await evaluate(required,'document.getElementById("prepare").requestSubmit()');
 await waitFor(()=>evaluate(required,'document.getElementById("status").textContent.includes("does not provide")'),'UV rejection');await evaluate(required,'document.getElementById("cancel").click()');
 await waitFor(()=>evaluate(rp.sessionId,'window.testResult'),'UV cancellation');
 console.log('PASS required user verification fails closed');
 const aborted=await request('get',get);await evaluate(rp.sessionId,'window.testAbort.abort()');
 const abortResult=await waitFor(()=>evaluate(rp.sessionId,'window.testResult'),'abort result');assert.match(abortResult.error,/AbortError/);
 await waitFor(()=>evaluate(ext.sessionId,'chrome.storage.session.get("pending").then(v=>!v.pending)'),'cancellation cleanup');console.log('PASS browser AbortController clears pending request');
 await call('Page.navigate',{url:'http://localhost:9323'},rp.sessionId);
 await waitFor(()=>evaluate(rp.sessionId,'location.port === "9323" && document.readyState === "complete"'),'unallowed site');
 const unallowed=await request('create',{...options,rp:{id:'localhost',name:'Unallowed RP'}});
 await evaluate(unallowed,'document.getElementById("prepare").requestSubmit()');
 await waitFor(()=>evaluate(unallowed,'document.getElementById("status").textContent.includes("Site not allowed")'),'origin rejection');await evaluate(unallowed,'document.getElementById("cancel").click()');
 console.log('PASS unallowed browser origin fails closed');
 console.log('ALL DESKTOP TESTS PASSED');
} finally {
 if(ext)await evaluate(ext.sessionId,'chrome.runtime.sendMessage({action:"detach"})').catch(()=>{});
 for(const targetId of targets)await call('Target.closeTarget',{targetId}).catch(()=>{});
 ws.close();unallowedServer.closeAllConnections();await new Promise(r=>unallowedServer.close(r));server.closeAllConnections();await new Promise(r=>server.close(r));
}
