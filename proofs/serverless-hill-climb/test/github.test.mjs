import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {jwtVerify,importPKCS8} from 'jose';
import {githubEvent,githubAlarm,pkcs8,ACK} from '../src/github.mjs';
const pair=generateKeyPairSync('rsa',{modulusLength:2048});
const pem=pair.privateKey.export({type:'pkcs1',format:'pem'});
const secret='test-only-webhook-secret';
const payload=()=>({action:'labeled',label:{name:'hill climb'},number:12,repository:{id:42,full_name:'r33drichards/example',owner:{id:57335981}},installation:{id:3},pull_request:{state:'open',base:{repo:{id:42}}}});
function fixture(){const map=new Map();map.set('github-app',{id:7,privateKey:pem,webhookSecret:secret});return {env:{GITHUB_OWNER_ID:'57335981'},now:()=>Date.now(),read:async k=>structuredClone(map.get(k)),save:async(k,v)=>map.set(k,structuredClone(v)),storage:{get:async k=>structuredClone(map.get(k)),put:async(k,v)=>map.set(k,structuredClone(v)),setAlarm:async()=>{},deleteAlarm:async()=>{}},map};}
async function request(p=payload(),signature=true,event='pull_request'){
 const body=JSON.stringify(p),key=await crypto.subtle.importKey('raw',new TextEncoder().encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
 const sig=Buffer.from(await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(body))).toString('hex');
 return new Request('https://example.test/github/events',{method:'POST',body,headers:{'X-Hub-Signature-256':'sha256='+(signature?sig:'0'.repeat(64)),'X-GitHub-Event':event,'X-GitHub-Delivery':'test-delivery-123'}});
}
test('signature, exact label and owner enforced',async()=>{const a=fixture();assert.equal((await githubEvent(a,await request(payload(),false))).status,401);const p=payload();p.label.name='hill-climb';assert.equal((await (await githubEvent(a,await request(p))).json()).status,'ignored');p.label.name='hill climb';p.repository.owner.id=999;assert.equal((await githubEvent(a,await request(p))).status,403);});
test('signed ping and ignored event do not create jobs',async()=>{const a=fixture();assert.equal((await (await githubEvent(a,await request({},true,'ping'))).json()).status,'pong');assert.equal((await (await githubEvent(a,await request(payload(),true,'issues'))).json()).status,'ignored');assert.equal(a.map.get('gh-queue'),undefined);});
test('PKCS1 conversion signs valid GitHub app JWT',async()=>{assert.ok(await importPKCS8(pkcs8(pem),'RS256'));});
function network(a,{postFails=false,wrongOwner=false,closed=false,label='hill climb'}={}){let posts=0;a.json=async(url,opts)=>{
 if(url.endsWith('/app/installations/3')){await jwtVerify(opts.headers.Authorization.slice(7),pair.publicKey,{issuer:'7'});return {app_id:7,account:{id:wrongOwner?999:57335981}};}
 if(url.endsWith('/access_tokens')){assert.deepEqual(JSON.parse(opts.body),{repository_ids:[42],permissions:{pull_requests:'write'}});return {token:'test-token'};}
 if(url.includes('/pulls/'))return {state:closed?'closed':'open',labels:[{name:label}]};
 if(url.endsWith('/comments')){posts++;assert.equal(JSON.parse(opts.body).body,ACK);if(postFails)throw Error('timeout after post');return {id:88};}
 throw Error('unexpected url');};return ()=>posts;}
test('signed event queues then comments once; redelivery and relabel deduped',async()=>{const a=fixture(),posts=network(a);assert.equal((await githubEvent(a,await request())).status,202);await githubAlarm(a);assert.equal(posts(),1);assert.equal((await a.read('gh:42:12')).status,'completed');assert.equal((await (await githubEvent(a,await request())).json()).duplicate,true);await githubAlarm(a);assert.equal(posts(),1);});
test('ambiguous POST never retries comment',async()=>{const a=fixture(),posts=network(a,{postFails:true});await githubEvent(a,await request());await githubAlarm(a);assert.equal((await a.read('gh:42:12')).status,'uncertain');await githubEvent(a,await request());await githubAlarm(a);assert.equal(posts(),1);});
test('crash at posting checkpoint fails closed',async()=>{const a=fixture(),posts=network(a);await githubEvent(a,await request());const job=await a.read('gh:42:12');job.status='posting';await a.save(job.key,job);await githubAlarm(a);assert.equal(posts(),0);assert.equal((await a.read(job.key)).status,'uncertain');});
test('installation owner rejected with bounded retries',async()=>{const a=fixture(),posts=network(a,{wrongOwner:true});await githubEvent(a,await request());for(let n=0;n<4;n++)await githubAlarm(a);assert.equal(posts(),0);assert.equal((await a.read('gh:42:12')).status,'failed');});
test('closed PR skipped without commenting',async()=>{const a=fixture(),posts=network(a,{closed:true});await githubEvent(a,await request());await githubAlarm(a);assert.equal(posts(),0);assert.equal((await a.read('gh:42:12')).status,'skipped');});

test('no-space alias completes and shares deduplication with spaced label',async()=>{const a=fixture(),posts=network(a,{label:'hillclimb'});const p=payload();p.label.name='hillclimb';assert.equal((await githubEvent(a,await request(p))).status,202);await githubAlarm(a);assert.equal(posts(),1);assert.equal((await a.read('gh:42:12')).status,'completed');assert.equal((await (await githubEvent(a,await request())).json()).duplicate,true);await githubAlarm(a);assert.equal(posts(),1);});
