const transportHash=async value=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value))),b=>b.toString(16).padStart(2,'0')).join('');
import { NativeMcp, LambdaMcp } from './mcp.mjs';
import { githubEvent, githubAlarm } from './github.mjs';
import { Agent } from '@earendil-works/pi-agent-core';
import { stream as streamResponses } from '@earendil-works/pi-ai/api/openai-responses';
import { createLocalJWKSet, jwtVerify } from 'jose';

const enc = new TextEncoder();
const dec = new TextDecoder();
const TEN_MINUTES = 600_000;
const SESSION_MS = 8 * 60 * 60_000;
const OPENAI_ISSUER = 'https://auth.openai.com';
const TOKEN_URL = OPENAI_ISSUER + '/api/accounts/oauth/token';
const RESOURCE = 'https://api.openai.com/v1';
const CALLBACK = 'http://127.0.0.1:1455/auth/callback';
const SCOPES = 'openid profile email offline_access resource.invoke chatgpt.tokens.use.direct';
const b64 = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64 = text => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const random = () => b64(crypto.getRandomValues(new Uint8Array(32)));
const hash = async text => b64(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(text))));
const escape = text => String(text).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fail = (message, status = 400) => { throw Object.assign(new Error(message), {safe: true, status}); };

const HEADERS = {
  'Cache-Control': 'no-store, private',
  'Referrer-Policy': 'same-origin',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Strict-Transport-Security': 'max-age=31536000',
  'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://github.com; base-uri 'none'; frame-ancestors 'none'",
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};
function page(body, status = 200, extra = {}) {
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Serverless Hill Climb · Admin</title><style>
  :root{color-scheme:dark;font-family:system-ui,sans-serif;background:#0b1120;color:#e2e8f0}body{max-width:680px;margin:8vh auto;padding:24px;line-height:1.6}h1{font-size:2.2rem;letter-spacing:-.04em}h2{font-size:1.2rem}section{background:#141e32;border:1px solid #2a3852;border-radius:16px;padding:24px;margin:24px 0}a{color:#93c5fd}button,.button{display:inline-block;background:#93c5fd;color:#0b1120;padding:12px 20px;border:0;border-radius:8px;font:inherit;font-weight:650;text-decoration:none;cursor:pointer}button.secondary{background:#26354c;color:#e2e8f0}input{width:100%;box-sizing:border-box;background:#0b1120;color:#fff;border:1px solid #526079;border-radius:8px;padding:12px;margin:8px 0 16px;font:inherit}.muted{color:#a4b2c8}.eyebrow{font-size:.8rem;letter-spacing:.12em;text-transform:uppercase;color:#93c5fd}code{overflow-wrap:anywhere}form{margin:12px 0}footer{font-size:.9rem;color:#a4b2c8}</style></head><body><div class="eyebrow">Serverless Hill Climb</div><h1>Your agent, your account.</h1>${body}<footer>Owner-only administration · Credentials stay server-side.</footer></body></html>`, {
    status, headers: {...HEADERS, 'Content-Type':'text/html; charset=utf-8', ...extra},
  });
}
function redirect(path, cookies = []) {
  const headers = new Headers({...HEADERS, Location:path});
  for (const cookie of cookies) headers.append('Set-Cookie', cookie);
  return new Response(null, {status:303, headers});
}
const cookie = (name, value, seconds) => `__Host-${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${seconds}`;
const csrfInput = session => `<input type="hidden" name="csrf" value="${escape(session.csrf)}">`;
function form(session, action, label, secondary = false) {
  return `<form method="post" action="${action}">${csrfInput(session)}<button${secondary?' class="secondary"':''}>${label}</button></form>`;
}
async function limitedText(body, limit) {
  if (!body) return '';
  const reader = body.getReader(); let size = 0; const chunks = [];
  for (;;) {
    const {done,value} = await reader.read(); if (done) break;
    size += value.length;
    if (size > limit) { await reader.cancel(); fail('Response or form is too large.', 413); }
    chunks.push(value);
  }
  const all = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { all.set(chunk, offset); offset += chunk.length; }
  return dec.decode(all);
}

// Worker routes are explicitly allowlisted. No public credential-export route.
const ROUTES = new Set(['/github/events','/webhook','/runs','/admin','/setup/callback','/auth/github','/auth/github/callback',
  '/ops/lambda-probe','/ops/verify','/admin/chatgpt/start','/admin/chatgpt','/admin/chatgpt/complete','/admin/chatgpt/disconnect','/admin/logout']);
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.origin !== env.PUBLIC_ORIGIN) return new Response('Wrong host', {status:421,headers:HEADERS});
    if (url.pathname === '/health' && request.method === 'GET') return Response.json({service:'serverless-hill-climb',admin:'deployed',webhook:'checkpointed',toolTransport:env.PI_TOOL_TRANSPORT || 'modal'}, {headers:HEADERS});
    if (url.pathname === '/') return redirect('/admin');
    if (!ROUTES.has(url.pathname)) return new Response('Not found', {status:404,headers:HEADERS});
    return env.AUTH.get(env.AUTH.idFromName('owner')).fetch(request);
  },
};

export class OwnerAuthority {
  constructor(state, env) {
    this.storage = state.storage; this.env = env;
    this.chain = Promise.resolve();
    this.fetcher = (...args) => fetch(...args);
    this.now = () => Date.now();
  }
  serial(fn) {
    const next = this.chain.then(fn); this.chain = next.catch(() => {}); return next;
  }
  async key() {
    if (!this.keyPromise) this.keyPromise = (async () => {
      const raw = unb64(this.env.VAULT_KEY || '');
      if (raw.length !== 32) fail('Secure storage is not configured.',503);
      return crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt','decrypt']);
    })();
    return this.keyPromise;
  }
  async seal(purpose, value) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:enc.encode(purpose)},await this.key(),enc.encode(JSON.stringify(value)));
    return b64(iv)+'.'+b64(new Uint8Array(cipher));
  }
  async open(purpose, value) {
    const parts = String(value).split('.'); if (parts.length !== 2) throw Error('invalid_cipher');
    return JSON.parse(dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(parts[0]),additionalData:enc.encode(purpose)},await this.key(),unb64(parts[1]))));
  }
  async read(name) { const raw = await this.storage.get(name); return raw ? this.open(name,raw) : undefined; }
  async save(name,value) { await this.storage.put(name,await this.seal(name,value)); }
  async readCookie(request,name) {
    const raw = (request.headers.get('Cookie') || '').split(';').map(s=>s.trim()).find(s=>s.startsWith(`__Host-${name}=`))?.slice(name.length+8);
    if (!raw || raw.length>8192) return;
    try { const value=await this.open('cookie:'+name,raw); if (value.expires>this.now()) return value; } catch {}
  }
  async setCookie(name,value,seconds) { return cookie(name,await this.seal('cookie:'+name,{...value,expires:this.now()+seconds*1000}),seconds); }
  async session(request) {
    const s = await this.readCookie(request,'session');
    if (s?.owner !== this.env.GITHUB_OWNER_ID || !s.sid || !s.csrf) return;
    if (s.epoch !== (await this.storage.get('epoch') || 0)) return;
    return s;
  }
  async json(url, options = {}) {
    // Workers rejects redirect:'error' before dispatch. Manual mode keeps secrets
    // on the intended origin; the non-2xx guard below rejects every redirect.
    const response = await this.fetcher(url,{...options,redirect:'manual',signal:AbortSignal.timeout(15_000),headers:{Accept:'application/json','User-Agent':'durable-pi-modal',...options.headers}});
    if (!response.ok) { await response.body?.cancel(); fail('The sign-in provider could not complete this request. Start a fresh sign-in.',502); }
    try { return JSON.parse(await limitedText(response.body,128*1024)); } catch (e) { if (e.safe) throw e; fail('Invalid provider response.',502); }
  }
  async consume(state) {
    const key=await hash(state), now=this.now();
    const used=await this.storage.get('used-flows') || {};
    for (const [k,v] of Object.entries(used)) if(v<now) delete used[k];
    if (used[key]) fail('This sign-in was already submitted. Start again.',409);
    if (Object.keys(used).length >= 64) fail('Too many sign-in attempts. Try again later.',429);
    used[key]=now+TEN_MINUTES;
    await this.storage.put('used-flows',used); // Reserve before one-use code dispatch.
  }
  async flow(request,purpose) {
    const value=await this.readCookie(request,'flow');
    if (!value || value.purpose!==purpose || new URL(request.url).searchParams.get('state')!==value.state) fail('Sign-in state expired or did not match. Return to the admin page.',400);
    await this.consume(value.state); return value;
  }
  async post(request,s) {
    if(request.method!=='POST') fail('Method not allowed.',405);
    if(request.headers.get('Origin')!==this.env.PUBLIC_ORIGIN) fail('Submit this form from the admin page.',403);
    if(!(request.headers.get('Content-Type') || '').startsWith('application/x-www-form-urlencoded')) fail('Invalid form.',415);
    const values=new URLSearchParams(await limitedText(request.body,20*1024));
    if (values.get('csrf')!==s.csrf) fail('Form expired. Reload the admin page.',403);
    return values;
  }
  fetch(request) {
    return this.serial(async()=> {
      try { return await this.route(request); }
      catch(e) { return page(`<section><h2>Request not completed</h2><p>${escape(e.safe?e.message:'The request could not be completed. No sensitive details have been logged.')}</p><a href="/admin">Return to admin</a></section>`,e.safe?e.status:500); }
    });
  }
  async route(request) {
    const url=new URL(request.url), path=url.pathname, origin=this.env.PUBLIC_ORIGIN;
    if (url.origin!==origin) fail('Wrong host.',421);
    if(path==='/github/events') return githubEvent(this,request);
    if(path==='/webhook' || path==='/runs') return this.webhook(request);
    if(path==='/ops/lambda-probe') {
      if(request.method!=='POST' || !this.env.VERIFY_KEY || request.headers.get('Authorization')!=='Bearer '+this.env.VERIFY_KEY) fail('Unauthorized.',401);
      if(this.env.PI_TOOL_TRANSPORT!=='lambda') fail('Lambda transport is not configured.',503);
      const session='pi-'+await transportHash('lambda-fixed-probe');
      const client=new LambdaMcp(this.fetcher,this.env.LAMBDA_CLIENT_SECRET,session);
      const result=await client.run("await fs.writeFile('/work/transport-proof.txt','pi-lambda-connected'); console.log(await fs.readFile('/work/transport-proof.txt','utf8'));");
      if(result.isError || !JSON.stringify(result).includes('pi-lambda-connected')) fail('Lambda transport probe failed.',502);
      return Response.json({transport:'lambda',status:'passed',modelConnected:!!await this.read('chatgpt'),modelVerified:(await this.read('inference-proof-v2'))?.status==='passed'},{headers:HEADERS});
    }
    if(path==='/ops/verify') {
      if(request.method!=='POST' || !this.env.VERIFY_KEY || request.headers.get('Authorization')!=='Bearer '+this.env.VERIFY_KEY) fail('Unauthorized.',401);
      // Fixed bounded diagnostic; cannot submit arbitrary prompts or export tokens.
      return Response.json(await this.verifyInference(),{headers:HEADERS});
    }
    const s=await this.session(request);
    const app=await this.read('github-app');
    if(path==='/admin' && request.method==='GET') {
      if (!app) return this.setupPage();
      if (!s) return page(`<section><h2>Sign in to administer your agent</h2><p>Access is restricted to <strong>${escape(this.env.GITHUB_OWNER_LOGIN)}</strong>.</p><a class="button" href="/auth/github">Continue with GitHub</a></section>`);
      const recent=await this.read('gh-last');
      return page(`<p>Signed in as ${escape(this.env.GITHUB_OWNER_LOGIN)}</p><section><h2>PR acknowledgement agent</h2><p>Install this app on selected repositories in your personal account. Label an open PR <code>hill climb</code> or <code>hillclimb</code>; the app comments once per PR.</p><a class="button" href="https://github.com/apps/${escape(app.slug)}/installations/new">Install on repositories</a><p>Webhook: <code>/github/events</code></p><p>Slice: fixed acknowledgement only. No model calls, code changes, merges, or Modal allocations.</p><p>Last job: ${escape(recent ? recent.status+' · '+recent.repo+'#'+recent.number : 'No matching delivery yet')}</p></section>${form(s,'/admin/logout','Sign out',true)}`);
    }
    if(path==='/setup/callback' && request.method==='GET') {
      if(app) fail('GitHub is already configured.',409);
      await this.flow(request,'manifest');
      const code=url.searchParams.get('code'); if(!code || !/^[a-zA-Z0-9_-]{10,200}$/.test(code)) fail('Missing GitHub setup code.');
      const data=await this.json(`https://api.github.com/app-manifests/${encodeURIComponent(code)}/conversions`,{method:'POST',headers:{'X-GitHub-Api-Version':'2022-11-28'}});
      if(String(data.owner?.id)!==this.env.GITHUB_OWNER_ID) fail('This app must be owned by the configured GitHub account. No configuration was saved.',403);
      if(!data.client_id || !data.client_secret || !data.id || !data.pem || !data.webhook_secret || !/^[a-zA-Z0-9-]+$/.test(data.slug || '')) fail('GitHub app response is incomplete.',502);
      await this.save('github-app',{id:data.id,clientId:data.client_id,clientSecret:data.client_secret,owner:this.env.GITHUB_OWNER_ID,privateKey:data.pem,webhookSecret:data.webhook_secret,slug:data.slug});
      // App credentials are encrypted and never exposed to the browser.
      return redirect('/auth/github',[cookie('flow','',0)]);
    }
    if(path==='/auth/github' && request.method==='GET') {
      if(!app) return redirect('/admin');
      const state=random(),verifier=random();
      const dest=new URL('https://github.com/login/oauth/authorize');
      dest.search=new URLSearchParams({client_id:app.clientId,redirect_uri:origin+'/auth/github/callback',state,code_challenge:await hash(verifier),code_challenge_method:'S256',login:this.env.GITHUB_OWNER_LOGIN}).toString();
      return redirect(dest.toString(),[await this.setCookie('flow',{purpose:'github',state,verifier},600)]);
    }
    if(path==='/auth/github/callback' && request.method==='GET') {
      if(!app) fail('GitHub is not configured.',503);
      const f=await this.flow(request,'github');
      const code=url.searchParams.get('code'); if(!code || url.searchParams.has('error')) fail('GitHub authorization was not completed.');
      const grant=await this.json('https://github.com/login/oauth/access_token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:app.clientId,client_secret:app.clientSecret,code,redirect_uri:origin+'/auth/github/callback',code_verifier:f.verifier})});
      if(typeof grant.access_token!=='string' || grant.error) fail('GitHub authorization failed.',403);
      const user=await this.json('https://api.github.com/user',{headers:{Authorization:`Bearer ${grant.access_token}`,'X-GitHub-Api-Version':'2022-11-28'}});
      if(String(user.id)!==this.env.GITHUB_OWNER_ID) fail('Only the configured GitHub owner can use this admin page.',403);
      // The GitHub access/refresh tokens are not needed after identity verification.
      const session={owner:this.env.GITHUB_OWNER_ID,sid:random(),csrf:random(),epoch:await this.storage.get('epoch') || 0};
      return redirect('/admin',[cookie('flow','',0),await this.setCookie('session',session,SESSION_MS/1000)]);
    }
    if(!s) fail('Sign in with GitHub first.',401);
    if(path==='/admin/logout') {
      await this.post(request,s);
      await this.storage.put('epoch',(await this.storage.get('epoch') || 0)+1);
      await this.storage.delete('chatgpt-pending');
      return redirect('/admin',[cookie('session','',0)]);
    }
    if(path==='/admin/chatgpt/start') {
      await this.post(request,s);
      const old=await this.read('chatgpt');
      let host=await this.storage.get('host');
      if(!host) {host='urn:uuid:'+crypto.randomUUID(); await this.storage.put('host',host);}
      await this.save('chatgpt-pending',{sid:s.sid,state:random(),nonce:random(),verifier:random(),expires:this.now()+TEN_MINUTES,status:'pending',clientId:old?.credential.clientId || 'dynamic_agent_client',subject:old?.identity.sub,host});
      return redirect('/admin/chatgpt');
    }
    if(path==='/admin/chatgpt' && request.method==='GET') {
      const pending=await this.pending(s);
      const dest=new URL(OPENAI_ISSUER+'/api/accounts/authorize');
      dest.search=new URLSearchParams({client_id:pending.clientId,agent_name_hint:'Durable Pi Modal',ext_agent_host_id:pending.host,response_type:'code',redirect_uri:CALLBACK,resource:RESOURCE,scope:SCOPES,state:pending.state,nonce:pending.nonce,code_challenge:await hash(pending.verifier),code_challenge_method:'S256'}).toString();
      return page(`<section><h2>Connect your ChatGPT account</h2><p>Open ChatGPT in a new tab and approve access for your personal agent.</p><a class="button" target="_blank" rel="noopener noreferrer" href="${escape(dest)}">Continue with ChatGPT</a><p>After approval, your browser may show a connection error at <code>127.0.0.1:1455</code>. Copy the <strong>complete URL</strong> from that tab’s address bar and paste it here.</p><form method="post" action="/admin/chatgpt/complete">${csrfInput(s)}<label for="callback">Final redirect URL</label><input id="callback" name="callback" type="url" required autocomplete="off" spellcheck="false" placeholder="http://127.0.0.1:1455/auth/callback?…"><button>Save ChatGPT connection</button></form><p class="muted">Only this private page should receive the URL. Never paste it into chat.</p></section><a href="/admin">Back to admin</a>`);
    }
    if(path==='/admin/chatgpt/complete') {
      const body=await this.post(request,s), pending=await this.pending(s);
      let cb;
      try { cb=new URL(body.get('callback')); } catch { fail('Paste the complete callback URL from this sign-in.'); }
      if(cb.origin!=='http://127.0.0.1:1455' || cb.pathname!=='/auth/callback' || cb.username || cb.password || cb.hash || cb.searchParams.get('state')!==pending.state || cb.searchParams.has('error') || !cb.searchParams.get('code')) fail('Callback URL or state did not match. No token exchange was attempted.');
      const clientId=cb.searchParams.get('client_id') || (pending.clientId!=='dynamic_agent_client'?pending.clientId:null);
      if(!clientId || clientId==='dynamic_agent_client' || (pending.clientId!=='dynamic_agent_client' && clientId!==pending.clientId)) fail('Missing or mismatched issued client ID.');
      pending.status='exchanging'; await this.save('chatgpt-pending',pending);
      try {
        const data=await this.token(new URLSearchParams({grant_type:'authorization_code',client_id:clientId,code:cb.searchParams.get('code'),code_verifier:pending.verifier,redirect_uri:CALLBACK,resource:RESOURCE}));
        const identity=await this.verifyIdentity(data.id_token,clientId,pending.nonce);
        if(pending.subject && identity.sub!==pending.subject) fail('This is a different ChatGPT account. Disconnect locally before switching accounts.',403);
        const credential=this.credential(data,clientId);
        await this.save('chatgpt',{status:'ready',credential,identity:{sub:identity.sub,email:identity.email},connectedAt:this.now()});
        await this.storage.delete('chatgpt-pending');
        return redirect('/admin');
      } catch(e) {
        await this.storage.delete('chatgpt-pending');
        throw e;
      }
    }
    if(path==='/admin/chatgpt/disconnect') {
      await this.post(request,s);
      await this.storage.delete(['chatgpt','chatgpt-pending']);
      return page('<section><h2>Disconnected locally</h2><p>The saved ChatGPT credentials have been removed from this agent. To revoke the authorization at OpenAI too, remove the app in your ChatGPT settings.</p><a href="/admin">Return to admin</a></section>');
    }
    fail('Not found.',404);
  }
  async setupPage() {
    const state=random();
    const origin=this.env.PUBLIC_ORIGIN;
    const manifest={name:'Serverless Hill Climb '+this.env.GITHUB_OWNER_LOGIN,url:origin,redirect_url:origin+'/setup/callback',callback_urls:[origin+'/auth/github/callback'],hook_attributes:{url:origin+'/github/events',active:true},public:false,default_permissions:{pull_requests:'write'},default_events:['pull_request'],description:'Acknowledge hill climb labels on selected owner repositories.'};
    return page(`<section><h2>One-time GitHub setup</h2><p>Create the private sign-in app under <strong>${escape(this.env.GITHUB_OWNER_LOGIN)}</strong>. GitHub will ask you to confirm its name. Requests pull-request read/write permission to post acknowledgements. Install only on repositories you want it to watch.</p><form method="post" action="https://github.com/settings/apps/new?state=${state}"><input type="hidden" name="manifest" value="${escape(JSON.stringify(manifest))}"><button>Set up with GitHub</button></form><p class="muted">After setup, sign in with GitHub to connect ChatGPT. Other GitHub accounts cannot claim this agent.</p></section>`,200,{'Set-Cookie':await this.setCookie('flow',{purpose:'manifest',state},600)});
  }
  async pending(s) {
    const p=await this.read('chatgpt-pending');
    if(!p || p.sid!==s.sid || p.expires<=this.now() || p.status!=='pending') fail('ChatGPT sign-in expired or was already submitted. Start a fresh connection.',409);
    return p;
  }
  async token(body) {return this.json(TOKEN_URL,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});}
  credential(data,clientId) {
    if(typeof data.access_token!=='string' || !data.access_token || typeof data.refresh_token!=='string' || !data.refresh_token || !Number.isFinite(data.expires_in) || data.expires_in<=180 || typeof data.scope!=='string' || !data.scope.split(/\s+/).includes('chatgpt.tokens.use.direct')) fail('ChatGPT plan usage was not granted. No credentials were saved.',403);
    return {type:'oauth',access:data.access_token,refresh:data.refresh_token,expires:this.now()+data.expires_in*1000-180_000,clientId,scopes:data.scope.split(/\s+/)};
  }
  async verifyIdentity(idToken,clientId,nonce) {
    if(typeof idToken!=='string') fail('OpenAI did not return a verifiable identity.',403);
    const jwks=await this.json(OPENAI_ISSUER+'/.well-known/jwks.json');
    try {
      const {payload}=await jwtVerify(idToken,createLocalJWKSet(jwks),{issuer:OPENAI_ISSUER,audience:clientId,algorithms:['RS256','ES256'],requiredClaims:['sub','exp','iat'],clockTolerance:5,currentDate:new Date(this.now())});
      if(payload.nonce!==nonce || typeof payload.sub!=='string' || !payload.sub) throw Error('identity');
      return payload;
    } catch { fail('ChatGPT identity validation failed. No credentials were saved.',403); }
  }


  async webhook(request) {
    if(!this.env.WEBHOOK_KEY || request.headers.get('Authorization')!=='Bearer '+this.env.WEBHOOK_KEY) fail('Unauthorized.',401);
    const url=new URL(request.url);
    if(url.pathname==='/runs' && request.method==='GET') {
      const id=url.searchParams.get('id');
      if(!/^[a-zA-Z0-9_-]{1,80}$/.test(id || '')) fail('Invalid event ID.');
      const run=await this.read('run:'+id); if(!run) fail('Not found.',404);
      return Response.json(run,{headers:HEADERS});
    }
    if(url.pathname!=='/webhook' || request.method!=='POST') fail('Method not allowed.',405);
    let body;try {body=JSON.parse(await limitedText(request.body,12000));}catch {fail('Invalid body.');}
    const {id,session,prompt,timestamp}=body || {};
    if(!/^[a-zA-Z0-9_-]{1,80}$/.test(id || '') || !/^[a-z0-9-]{1,64}$/.test(session || '') || typeof prompt!=='string' || prompt.length>4000 || !Number.isFinite(timestamp) || Math.abs(this.now()-timestamp)>300000) fail('Invalid event or expired timestamp.');
    const digest=await hash(JSON.stringify({session,prompt}));
    const prior=await this.read('run:'+id);
    if(prior) {
      if(prior.digest!==digest) fail('Event ID conflict.',409);
      if(prior.status==='queued') await this.storage.setAlarm(this.now()+100);
      return Response.json({id,status:prior.status,duplicate:true},{headers:HEADERS});
    }
    if(await this.storage.get('active-run')) fail('An owner run is already active.',409);
    const count=await this.storage.get('run-count') || 0;
    if(count>=100) fail('Run retention cap reached.',429);
    const run={id,session,prompt,digest,status:'queued',createdAt:this.now(),deadline:this.now()+240000,tools:[]};
    await this.save('run:'+id,run);
    await this.storage.put('run-count',count+1);
    await this.storage.put('active-run',id);
    await this.storage.setAlarm(this.now()+100);
    return Response.json({id,status:'queued',duplicate:false},{status:202,headers:HEADERS});
  }
  alarm() {
    return this.serial(async()=>{
      if(await githubAlarm(this)) return;
      const id=await this.storage.get('active-run'); if(!id) return;
      const run=await this.read('run:'+id);
      if(!run) {await this.storage.delete('active-run');return;}
      if(['completed','failed','interrupted'].includes(run.status)) {await this.storage.delete('active-run');return;}
      if(run.status!=='queued') {
        run.status='interrupted';run.reason='uncertain-checkpoint-no-automatic-replay';
        await this.releaseLease(run);
        await this.save('run:'+id,run);await this.storage.delete('active-run');return;
      }
      run.status='running';await this.save('run:'+id,run);
      // Alarm is a recovery watchdog, not an automatic replay of side effects.
      await this.storage.setAlarm(run.deadline+1000);
      try {
        const credential=await this.modelCredential();
        const proof=await this.read('inference-proof-v2');
        if(proof?.status!=='passed') throw Error('unverified-model');
        let turns=0,completed=0,transport;
        const lambda=this.env.PI_TOOL_TRANSPORT==='lambda';
        if(this.env.PI_TOOL_TRANSPORT && !['lambda','modal'].includes(this.env.PI_TOOL_TRANSPORT))throw Error('invalid-tool-transport');
        run.transport=lambda?'lambda':'modal';
        const model={id:proof.model,name:proof.model,api:'openai-responses',provider:'openai',baseUrl:'https://api.openai.com/v1',reasoning:false,input:['text'],cost:{input:0,output:0,cacheRead:0,cacheWrite:0},contextWindow:32000,maxTokens:1024};
        const check=()=>{if(this.now()>run.deadline) throw Error('deadline');if(run.tools.some(t=>t.status==='intent'||t.status==='uncertain'))throw Error('prior-tool-uncertain-no-replay');};
        const tool={name:'run_js',label:lambda?'JavaScript in Lambda':'JavaScript in isolated Modal engine',description:lambda?'Execute JavaScript in mcp-js on AWS Lambda. Await fs.writeFile, fs.readFile and fs.exists under /work/. Files persist in this session; never rely on live variables. Use console.log for output. No Node imports, network or subprocess.':'Execute JavaScript in mcp-js. fs.writeFile(path,text), fs.readFile(path), fs.exists(path) are available ONLY below /data/workspace/. Await filesystem calls. console.log results. No Node imports, network or subprocess. Tool calls share one sandbox during this run. Files persist; do not rely on JavaScript heap persistence.',
          parameters:{type:'object',properties:{code:{type:'string'}},required:['code'],additionalProperties:false},
          execute:async(callId,args)=>{
            check();if(run.tools.length>=4 || typeof args.code!=='string' || args.code.length>8192) throw Error('tool-budget');
            const call=await transportHash(id+':'+callId);
            const entry={call,status:'intent'};run.tools.push(entry);await this.save('run:'+id,run);
            if(!transport && lambda){transport=new LambdaMcp(this.fetcher,this.env.LAMBDA_CLIENT_SECRET,'pi-'+await transportHash(run.session));await transport.initialize();}
            if(!transport){
              run.lease={id:await transportHash('mcp:'+id),status:'intent'};await this.save('run:'+id,run);
              const lease=await this.lifecycle('acquire',{session:run.session,lease:run.lease.id});
              if(lease.lease!==run.lease.id)throw Error('lease-mismatch');
              run.lease.status='active';run.lease.sandbox=lease.sandbox;await this.save('run:'+id,run);
              transport=new NativeMcp(this.fetcher,lease);await transport.initialize();
            }
            let result;
            try {result=await transport.run(args.code);}
            catch {entry.status='uncertain';await this.save('run:'+id,run);throw Error('direct-mcp-failed-no-replay');}
            entry.status='completed';entry.transport=run.transport;entry.sandbox=transport.lease.sandbox;entry.isError=!!result.isError;
            entry.result=result;await this.save('run:'+id,run);
            return {content:[{type:'text',text:JSON.stringify(result)}],details:{sandbox:entry.sandbox}};
          }};
        const agent=new Agent({initialState:{model,systemPrompt:lambda?'You are the owner personal Pi agent. Use run_js for requested file operations under /work/. Report only observed results. Files persist within this session, but live JavaScript variables do not. Never claim success without checking output.':'You are the owner personal Pi agent. Use run_js for requested file operations. Report only observed results. Never claim a tool succeeded without checking its output. Tool calls share a sandbox within this run. Files persist across runs; do not rely on JavaScript heap persistence.',tools:[tool]},toolExecution:'sequential',
          streamFn:async(m,c,o)=>{
            check();if(++turns>4) throw Error('turn-budget');
            run.phase='model';run.turns=turns;await this.save('run:'+id,run);
            return streamResponses(m,c,{...o,apiKey:credential.access,maxTokens:1024,maxRetries:0,signal:AbortSignal.timeout(45000),
              fetch:(u,opts)=>this.fetcher(u,{...opts,redirect:'manual'}),onPayload:p=>({...p,store:false,stream:true}),
              onProviderStreamEvent:e=>{if(e.type==='response.completed') completed++;}});
          }});
        await agent.prompt(run.prompt);
        const last=agent.state.messages.filter(m=>m.role==='assistant').at(-1);
        run.transcript=agent.state.messages;
        // Error messages may contain provider bodies; redact before durable storage.
        for(const msg of run.transcript) if(msg.errorMessage) msg.errorMessage='provider-request-failed';
        run.output=(last?.content || []).filter(c=>c.type==='text').map(c=>c.text).join('').slice(0,8192);
        run.status=completed===turns && last?.stopReason==='stop' && run.tools.every(t=>t.status==='completed' && !t.isError)?'completed':'failed';
        run.completedModelResponses=completed;
      } catch {run.status='failed';run.reason='bounded-run-failed-no-automatic-replay';}
      if(!await this.releaseLease(run)){run.status='failed';run.reason='sandbox-cleanup-unverified';}
      run.finishedAt=this.now();await this.save('run:'+id,run);
      await this.storage.delete('active-run');await this.storage.deleteAlarm();
    });
  }
  async lifecycle(operation,body) {
    if(!this.env.BROKER_KEY || !this.env.BROKER_URL)throw Error('lifecycle-not-configured');
    const response=await this.fetcher(this.env.BROKER_URL+'/leases/'+operation,{method:'POST',redirect:'manual',headers:{Authorization:'Bearer '+this.env.BROKER_KEY,'Content-Type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(60000)});
    if(!response.ok){await response.body?.cancel();throw Error('lifecycle-failed');}
    return JSON.parse(await limitedText(response.body,8192));
  }
  async releaseLease(run) {
    if(!run.lease)return true;
    try {
      const result=await this.lifecycle('release',{lease:run.lease.id});
      if(result.lease!==run.lease.id || result.terminated!==true)throw Error('release-unverified');
      run.lease.status='released';run.lease.terminated=true;
      for(const entry of run.tools)entry.terminated=true;
      return true;
    }catch{run.lease.status='cleanup-unverified';return false;}
  }
  async verifyInference() {
    const previous=await this.read('inference-proof-v2');
    if(previous) return previous; // One model attempt, durable before dispatch.
    const credential=await this.modelCredential();
    const pending={status:'in-progress',phase:'catalog',startedAt:this.now(),pi:'1.4.0'};
    await this.save('inference-proof-v2',pending);
    let result;
    try {
      const response=await this.fetcher('https://api.openai.com/v1/models',{
        headers:{Authorization:'Bearer '+credential.access},redirect:'manual',signal:AbortSignal.timeout(15000)});
      if(!response.ok) {
        await response.body?.cancel();
        result={...pending,status:'blocked',phase:'catalog',httpStatus:response.status};
      } else {
        pending.phase='catalog-parse';
        const catalog=JSON.parse(await limitedText(response.body,4*1024*1024));
        pending.phase='catalog-select';
        const models=(catalog.models || []).filter(m=>m.visibility==='list' && typeof m.slug==='string');
        const selected=models.find(m=>m.slug==='gpt-6.1-sol') || models[0];
        if(!selected) result={...pending,status:'blocked',phase:'catalog',reason:'no-visible-models'};
        else {
          pending.phase='inference'; pending.model=selected.slug;
          await this.save('inference-proof-v2',pending);
          let completed=false, providerCode, httpStatus;
          const model={id:selected.slug,name:selected.display_name || selected.slug,api:'openai-responses',provider:'openai',baseUrl:'https://api.openai.com/v1',reasoning:false,input:['text'],cost:{input:0,output:0,cacheRead:0,cacheWrite:0},contextWindow:32000,maxTokens:256};
          const agent=new Agent({initialState:{model,systemPrompt:'Reply with exactly PI_AUTH_OK. No tools.',tools:[]},
            streamFn:(m,c,o)=>streamResponses(m,c,{...o,apiKey:credential.access,maxTokens:256,maxRetries:0,
              signal:AbortSignal.timeout(45000),fetch:(url,opts)=>this.fetcher(url,{...opts,redirect:'manual'}),
              onPayload:p=>({...p,store:false,stream:true}),
              onResponse:r=>{httpStatus=r.status;},
              onProviderStreamEvent:e=>{if(e.type==='response.completed') completed=true;
                const code=e.response?.error?.code || e.error?.code;
                if(typeof code==='string' && /^[a-z0-9_]{1,100}$/.test(code)) providerCode=code;}})});
          await agent.prompt('Verify the saved ChatGPT authorization. Reply PI_AUTH_OK.');
          const last=agent.state.messages.filter(m=>m.role==='assistant').at(-1);
          const text=last?.content?.filter(c=>c.type==='text').map(c=>c.text).join('') || '';
          // Never persist provider error bodies or arbitrary output: boolean proof only.
          result={...pending,status:completed && last?.stopReason!=='error' && text.trim()==='PI_AUTH_OK'?'passed':'blocked',
            completed,expectedOutput:text.trim()==='PI_AUTH_OK',stopReason:last?.stopReason || 'missing',httpStatus,providerCode};
        }
      }
    } catch(e) {result={...pending,status:'blocked',reason:e.safe && e.status===413?'catalog-too-large':({TypeError:'type-error',SyntaxError:'invalid-json',TimeoutError:'timeout',AbortError:'aborted'}[e.name] || 'verification-exception')};}
    result.finishedAt=this.now();
    await this.save('inference-proof-v2',result);
    return result;
  }
  // Internal integration seam for the webhook/Pi runtime. Not an HTTP route or
  // Durable Object RPC export: this class uses only the fetch interface.
  async withModelCredential(fn) {
    return this.serial(async()=>fn(await this.modelCredential()));
  }
  async modelCredential() {
      let model=await this.read('chatgpt');
      if(!model || model.status!=='ready') fail('Reconnect ChatGPT from admin.',409);
      if(model.credential.expires<=this.now()) {
        model.status='refreshing'; await this.save('chatgpt',model);
        try {
          const old=model.credential;
          const grant=await this.token(new URLSearchParams({grant_type:'refresh_token',client_id:old.clientId,refresh_token:old.refresh,resource:RESOURCE}));
          model.credential=this.credential(grant,old.clientId);model.status='ready';
          await this.save('chatgpt',model);
        } catch(e) { model.status='reconnect-required'; await this.save('chatgpt',model); throw e; }
      }
      return model.credential;
  }
}
