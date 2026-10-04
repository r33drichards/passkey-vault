import { DurableObject } from 'cloudflare:workers';
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse, type WebAuthnCredential, type RegistrationResponseJSON, type AuthenticationResponseJSON } from '@simplewebauthn/server';
import { randomToken, hash, equalSecret, encrypt, decrypt, b64, unb64 } from './crypto';
import { parseSSHKey, verifySSHSignature, SSH_NAMESPACE, type SSHKey } from './ssh';
import { parseAccount, totp, toURI, type Account } from './totp';
export interface Env { VAULT: DurableObjectNamespace<Vault>; ASSETS: Fetcher; APP_ORIGIN: string; VAULT_KEY: string; SETUP_KEY: string }
type Credential = { id: string; publicKey: string; counter: number; transports?: WebAuthnCredential['transports']; name: string; created: number };
type Challenge = { challenge: string; kind: 'setup'|'add'|'login'|'ssh'; expires: number; session?: string; name?: string; keyId?: string };
type Session = { expires: number; verified: number };
class HTTPError extends Error { constructor(public status: number, message: string) { super(message); } }
function json(value: unknown, status=200, headers: Record<string,string> = {}) { return Response.json(value, {status, headers}); }
function cookie(req: Request, name: string): string { return req.headers.get('cookie')?.split(';').map(s=>s.trim()).find(s=>s.startsWith(name+'='))?.slice(name.length+1) || ''; }
function cookieHeader(req: Request, name: string, value: string, age: number): string { return `${name}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${age}${new URL(req.url).protocol === 'https:' ? '; Secure' : ''}`; }
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
function secure(response: Response): Response {
  const out = new Response(response.body, response); const h = out.headers;
  h.set('Cache-Control','no-store'); h.set('Content-Security-Policy',CSP); h.set('X-Content-Type-Options','nosniff'); h.set('Referrer-Policy','no-referrer'); h.set('X-Frame-Options','DENY');
  h.set('Permissions-Policy','camera=(self), microphone=(), geolocation=()'); h.set('Strict-Transport-Security','max-age=31536000'); return out;
}
export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    try {
      const configured = new URL(env.APP_ORIGIN), url = new URL(req.url);
      if (configured.origin !== env.APP_ORIGIN || (configured.protocol !== 'https:' && configured.hostname !== 'localhost')) throw new HTTPError(503,'Configure APP_ORIGIN with your HTTPS origin');
      if (url.origin !== env.APP_ORIGIN) throw new HTTPError(403,'Origin not allowed');
      if (url.pathname.startsWith('/api/')) {
        if (!env.VAULT_KEY || !env.SETUP_KEY || env.SETUP_KEY.length < 32) throw new HTTPError(503,'Vault secrets are not configured');
        if (req.method === 'POST' && req.headers.get('origin') !== env.APP_ORIGIN) throw new HTTPError(403,'Origin not allowed');
        if (req.headers.get('sec-fetch-site') === 'cross-site') throw new HTTPError(403,'Cross-site request rejected');
        return secure(await env.VAULT.get(env.VAULT.idFromName('personal-vault')).fetch(req));
      }
      if (!['GET','HEAD'].includes(req.method)) throw new HTTPError(405,'Method not allowed');
      return secure(await env.ASSETS.fetch(req));
    } catch (e) { return secure(json({error:e instanceof HTTPError ? e.message : 'Request failed'},e instanceof HTTPError ? e.status : 500)); }
  }
};
export class Vault extends DurableObject<Env> {
  async fetch(req: Request): Promise<Response> {
    // Serialize verification and state commits, including crypto awaits, so a challenge,
    // credential counter, or one-time setup cannot be raced by another request.
    return this.ctx.blockConcurrencyWhile(async () => {
      try { return await this.route(req); }
      catch (e) { return json({error: e instanceof HTTPError ? e.message : 'Unable to complete request'}, e instanceof HTTPError ? e.status : 500); }
    });
  }
  async body(req: Request): Promise<Record<string,unknown>> {
    if (!req.headers.get('content-type')?.startsWith('application/json')) throw new HTTPError(415,'Expected JSON');
    if (Number(req.headers.get('content-length')) > 16384) throw new HTTPError(413,'Request too large');
    const reader = req.body?.getReader(); if (!reader) throw new HTTPError(400,'Expected JSON object');
    const parts: Uint8Array[] = []; let size=0;
    while (true) { const {value,done}=await reader.read(); if (done) break; size+=value.byteLength; if(size>16384){await reader.cancel();throw new HTTPError(413,'Request too large');} parts.push(value); }
    const bytes = new Uint8Array(size); let offset=0; for(const p of parts){bytes.set(p,offset);offset+=p.length;}
    try { const data=JSON.parse(new TextDecoder().decode(bytes)); if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error(); return data; }
    catch { throw new HTTPError(400,'Expected JSON object'); }
  }
  async session(req: Request, recent=false): Promise<{id:string; data:Session}> {
    const token=cookie(req,'vault_session'); if (!token) throw new HTTPError(401,'Sign in with your passkey');
    const id=await hash(token), data=await this.ctx.storage.get<Session>('session:'+id);
    if (!data || data.expires<Date.now()) throw new HTTPError(401,'Session expired. Sign in again');
    if (recent && Date.now()-data.verified>120000) throw new HTTPError(428,'Confirm your passkey again to continue');
    return {id,data};
  }
  async takeChallenge(req: Request, kind: string): Promise<Challenge> {
    const token=cookie(req,'vault_challenge'), id='challenge:'+await hash(token);
    const value=await this.ctx.storage.get<Challenge>(id); await this.ctx.storage.delete(id);
    if(!token || !value || value.kind!==kind || value.expires<Date.now()) throw new HTTPError(400,'Passkey request expired. Try again');
    return value;
  }
  async rate(req: Request): Promise<void> {
    const bucket=Math.floor(Date.now()/60000), ip=req.headers.get('CF-Connecting-IP') || 'local';
    const id=`rate:${bucket}:${await hash(ip)}`; const count=(await this.ctx.storage.get<number>(id)) || 0;
    if(count>=30) throw new HTTPError(429,'Too many attempts. Try again in a minute');
    await this.ctx.storage.put(id,count+1); await this.scheduleCleanup();
  }
  async scheduleCleanup() { if(await this.ctx.storage.getAlarm()===null) await this.ctx.storage.setAlarm(Date.now()+600000); }
  async alarm() {
    // Bounded lists; continue cleanup if a prefix ever exceeds one page.
    for(const prefix of ['session:','challenge:','rate:']) {
      let start: string|undefined;
      while(true){ const rows=await this.ctx.storage.list<Session|Challenge|number>({prefix,startAfter:start,limit:500}); if(!rows.size)break;
        const stale:string[]=[]; for(const [k,v] of rows){start=k;if(prefix==='rate:' ? Number(k.split(':')[1])<Math.floor(Date.now()/60000)-2 : (v as Session).expires<Date.now())stale.push(k);} if(stale.length)await this.ctx.storage.delete(stale);if(rows.size<500)break;
      }
    }
    await this.ctx.storage.setAlarm(Date.now()+600000);
  }
  async route(req: Request): Promise<Response> {
    const path=new URL(req.url).pathname;
    if (req.method==='GET' && path==='/api/status') {
      const credentials=await this.ctx.storage.get<Credential[]>('credentials') || [];
      let signedIn=false;try{await this.session(req);signedIn=true;}catch{}
      return json({initialized:credentials.length>0,signedIn});
    }
    if (req.method==='GET' && path==='/api/accounts') {
      await this.session(req); const entries=await this.ctx.storage.list<string>({prefix:'account:'}); const now=Date.now();
      const accounts=await Promise.all([...entries].map(async ([id,cipher])=>{const a=await decrypt<Account>(cipher,this.env.VAULT_KEY,id);return {id:id.slice(8),issuer:a.issuer,label:a.label,digits:a.digits,period:a.period,code:await totp(a,now)};}));
      return json({accounts,now});
    }
    if(req.method==='GET' && path==='/api/passkeys') {await this.session(req);const credentials=await this.ctx.storage.get<Credential[]>('credentials')||[];return json({passkeys:credentials.map(c=>({id:c.id,name:c.name,created:c.created}))});}
    if(req.method==='GET' && path==='/api/ssh-keys') {await this.session(req);return json({keys:await this.ctx.storage.get<SSHKey[]>('sshKeys')||[]});}
    if(req.method!=='POST') throw new HTTPError(404,'Not found');
    const body=await this.body(req);
    if(path.startsWith('/api/auth/') || path.startsWith('/api/setup/') || path.startsWith('/api/recovery/')) await this.rate(req);
    const rpID=new URL(this.env.APP_ORIGIN).hostname;
    if(path==='/api/ssh-keys/add') {
      await this.session(req,true);const keys=await this.ctx.storage.get<SSHKey[]>('sshKeys')||[];if(keys.length>=10)throw new HTTPError(400,'Maximum 10 SSH recovery keys');
      if(typeof body.publicKey!=='string'||body.publicKey.length>4096)throw new HTTPError(400,'Paste an SSH public key');
      let key;try{key=await parseSSHKey(body.publicKey);}catch(e){throw new HTTPError(400,(e as Error).message);}
      if(keys.some(k=>k.id===key.id))throw new HTTPError(409,'SSH key already registered');
      keys.push({...key,name:String(body.name||'SSH recovery key').trim().slice(0,80),created:Date.now()});await this.ctx.storage.put('sshKeys',keys);return json({id:key.id});
    }
    if(path==='/api/ssh-keys/delete') {
      await this.session(req,true);const keys=await this.ctx.storage.get<SSHKey[]>('sshKeys')||[];await this.ctx.storage.put('sshKeys',keys.filter(k=>k.id!==body.id));
      const sessions=await this.ctx.storage.list({prefix:'session:'});await this.ctx.storage.delete([...sessions.keys()]);return json({ok:true},200,{'Set-Cookie':cookieHeader(req,'vault_session','',0)});
    }
    if(path==='/api/recovery/options') {
      if(typeof body.publicKey!=='string')throw new HTTPError(400,'Paste your SSH public key');let key;try{key=await parseSSHKey(body.publicKey);}catch{throw new HTTPError(403,'Recovery key not recognized');}
      const keys=await this.ctx.storage.get<SSHKey[]>('sshKeys')||[];if(!keys.some(k=>k.id===key.id))throw new HTTPError(403,'Recovery key not recognized');
      const expires=Date.now()+300000;
      const challenge=JSON.stringify({purpose:'Sign in to Passkey Vault',origin:this.env.APP_ORIGIN,namespace:SSH_NAMESPACE,key:key.id,nonce:randomToken(),expires:new Date(expires).toISOString()})+'\n';
      const token=randomToken();await this.ctx.storage.put('challenge:'+await hash(token),{challenge,kind:'ssh',expires,keyId:key.id} satisfies Challenge);await this.scheduleCleanup();
      return json({challenge,expires,namespace:SSH_NAMESPACE},200,{'Set-Cookie':cookieHeader(req,'vault_challenge',token,300)});
    }
    if(path==='/api/recovery/verify') {
      const c=await this.takeChallenge(req,'ssh');const keys=await this.ctx.storage.get<SSHKey[]>('sshKeys')||[],key=keys.find(k=>k.id===c.keyId);
      if(!key||typeof body.signature!=='string'||!await verifySSHSignature(key.publicKey,c.challenge,body.signature))throw new HTTPError(403,'Invalid SSH signature. Start a new recovery challenge');
      // Recovery revokes existing sessions. SSH recovery grants a short-lived owner session
      // so a lost passkey can be replaced without requiring the missing authenticator.
      const sessions=await this.ctx.storage.list({prefix:'session:'});await this.ctx.storage.delete([...sessions.keys()]);return await this.newSession(req);
    }
    if(path==='/api/setup/options' || path==='/api/passkeys/options') {
      const credentials=await this.ctx.storage.get<Credential[]>('credentials')||[];
      const setup=path.startsWith('/api/setup/'); let sessionId:string|undefined;
      if(setup){if(credentials.length)throw new HTTPError(409,'Vault is already set up');if(typeof body.setupKey!=='string' || !await equalSecret(body.setupKey,this.env.SETUP_KEY))throw new HTTPError(403,'Invalid setup key');}
      else {sessionId=(await this.session(req,true)).id;if(credentials.length>=10)throw new HTTPError(400,'Maximum 10 passkeys');}
      let userID=await this.ctx.storage.get<string>('userID'); if(!userID){userID=randomToken();await this.ctx.storage.put('userID',userID);}
      const name=String(body.name||'My passkey').trim().slice(0,80); if(!name)throw new HTTPError(400,'Name this passkey');
      const options=await generateRegistrationOptions({rpName:'Passkey Vault',rpID,userID:unb64(userID),userName:'owner',userDisplayName:'Vault owner',attestationType:'none',authenticatorSelection:{residentKey:'required',userVerification:'required'},excludeCredentials:credentials.map(c=>({id:c.id,transports:c.transports}))});
      const token=randomToken();await this.ctx.storage.put('challenge:'+await hash(token),{challenge:options.challenge,kind:setup?'setup':'add',expires:Date.now()+120000,session:sessionId,name} satisfies Challenge);await this.scheduleCleanup();
      return json({options},200,{'Set-Cookie':cookieHeader(req,'vault_challenge',token,120)});
    }
    if(path==='/api/setup/verify' || path==='/api/passkeys/verify') {
      const setup=path.startsWith('/api/setup/');const c=await this.takeChallenge(req,setup?'setup':'add'); const credentials=await this.ctx.storage.get<Credential[]>('credentials')||[];
      if(setup && credentials.length)throw new HTTPError(409,'Vault is already set up');
      if(!setup && (await this.session(req,true)).id!==c.session)throw new HTTPError(403,'Session changed');
      if(credentials.length>=10)throw new HTTPError(400,'Maximum 10 passkeys');
      let result;try {result=await verifyRegistrationResponse({response:body.response as RegistrationResponseJSON,expectedChallenge:c.challenge,expectedOrigin:this.env.APP_ORIGIN,expectedRPID:rpID,requireUserVerification:true});}catch{throw new HTTPError(400,'Passkey registration failed');}
      if(!result.verified || !result.registrationInfo)throw new HTTPError(400,'Passkey registration failed');
      const credential=result.registrationInfo.credential;if(credentials.some(x=>x.id===credential.id))throw new HTTPError(409,'Passkey already registered');
      credentials.push({id:credential.id,publicKey:b64(credential.publicKey),counter:credential.counter,transports:credential.transports,name:c.name||'My passkey',created:Date.now()});await this.ctx.storage.put('credentials',credentials);
      return setup ? await this.newSession(req) : json({ok:true});
    }
    if(path==='/api/auth/options') {
      const credentials=await this.ctx.storage.get<Credential[]>('credentials')||[];if(!credentials.length)throw new HTTPError(409,'Set up the vault first');
      const options=await generateAuthenticationOptions({rpID,userVerification:'required'}); const token=randomToken();
      await this.ctx.storage.put('challenge:'+await hash(token),{challenge:options.challenge,kind:'login',expires:Date.now()+120000} satisfies Challenge);await this.scheduleCleanup();
      return json({options},200,{'Set-Cookie':cookieHeader(req,'vault_challenge',token,120)});
    }
    if(path==='/api/auth/verify') {
      const c=await this.takeChallenge(req,'login');const credentials=await this.ctx.storage.get<Credential[]>('credentials')||[];
      const response=body.response as AuthenticationResponseJSON;const credential=credentials.find(x=>x.id===response?.id);if(!credential)throw new HTTPError(403,'Unknown passkey');
      let result;try{result=await verifyAuthenticationResponse({response,expectedChallenge:c.challenge,expectedOrigin:this.env.APP_ORIGIN,expectedRPID:rpID,credential:{id:credential.id,publicKey:unb64(credential.publicKey),counter:credential.counter,transports:credential.transports},requireUserVerification:true});}catch{throw new HTTPError(403,'Passkey verification failed');}
      if(!result.verified)throw new HTTPError(403,'Passkey verification failed');credential.counter=result.authenticationInfo.newCounter;await this.ctx.storage.put('credentials',credentials);
      return await this.newSession(req);
    }
    if(path==='/api/logout'){const token=cookie(req,'vault_session');if(token)await this.ctx.storage.delete('session:'+await hash(token));return json({ok:true},200,{'Set-Cookie':cookieHeader(req,'vault_session','',0)});}
    if(path==='/api/accounts/add') {
      await this.session(req);const entries=await this.ctx.storage.list({prefix:'account:'});if(entries.size>=200)throw new HTTPError(400,'Maximum 200 accounts');
      let account:Account;try{account=parseAccount(body);}catch(e){throw new HTTPError(400,(e as Error).message);}
      const id=crypto.randomUUID(), storageId='account:'+id;await this.ctx.storage.put(storageId,await encrypt(account,this.env.VAULT_KEY,storageId));return json({id});
    }
    if(path==='/api/accounts/delete') {await this.session(req,true);if(typeof body.id!=='string'||!/^[a-f0-9-]{36}$/.test(body.id))throw new HTTPError(400,'Invalid account');await this.ctx.storage.delete('account:'+body.id);return json({ok:true});}
    if(path==='/api/passkeys/delete') {
      await this.session(req,true);const credentials=await this.ctx.storage.get<Credential[]>('credentials')||[];if(credentials.length<=1)throw new HTTPError(400,'Keep at least one passkey');
      const remaining=credentials.filter(c=>c.id!==body.id);if(remaining.length===credentials.length)throw new HTTPError(404,'Passkey not found');await this.ctx.storage.put('credentials',remaining);
      // Revoking a passkey also revokes all sessions, including the current one.
      const sessions=await this.ctx.storage.list({prefix:'session:'});await this.ctx.storage.delete([...sessions.keys()]);return json({ok:true},200,{'Set-Cookie':cookieHeader(req,'vault_session','',0)});
    }
    if(path==='/api/export') {await this.session(req,true);const entries=await this.ctx.storage.list<string>({prefix:'account:'});const accounts=await Promise.all([...entries].map(async([id,cipher])=>toURI(await decrypt<Account>(cipher,this.env.VAULT_KEY,id))));return json({version:1,accounts});}
    throw new HTTPError(404,'Not found');
  }
  async newSession(req: Request): Promise<Response> {
    const old=cookie(req,'vault_session');if(old)await this.ctx.storage.delete('session:'+await hash(old));const token=randomToken();
    await this.ctx.storage.put('session:'+await hash(token),{expires:Date.now()+900000,verified:Date.now()} satisfies Session);await this.scheduleCleanup();
    return json({ok:true},200,{'Set-Cookie':cookieHeader(req,'vault_session',token,900)});
  }
}
