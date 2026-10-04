import { describe,it,expect,beforeEach } from 'vitest';
import { SELF,env,runInDurableObject,reset } from 'cloudflare:test';
import { totp,parseAccount,toURI,base32 } from '../src/totp';
import { encrypt,decrypt,hash,b64 } from '../src/crypto';
import { parseSSHKey,verifySSHSignature,SSH_NAMESPACE } from '../src/ssh';
import fixtures from './fixtures/ssh.json';
const origin='http://localhost:8787';
const req=(path:string,body?:unknown,cookie?:string,originHeader=origin)=>SELF.fetch(origin+'/api/'+path,{method:body===undefined?'GET':'POST',headers:{'Content-Type':'application/json',Origin:originHeader,...(cookie?{Cookie:cookie}:{})},body:body===undefined?undefined:JSON.stringify(body)});
const stub=()=>env.VAULT.get(env.VAULT.idFromName('personal-vault'));
async function seed(){const token='test-session';await runInDurableObject(stub(),async(_,ctx)=>{await ctx.storage.put('session:'+await hash(token),{verified:Date.now(),expires:Date.now()+900000});await ctx.storage.put('credentials',[{id:'test-credential',publicKey:'invalid-test-key',counter:0,name:'Test',created:Date.now()}]);});return 'vault_session='+token;}
beforeEach(async()=>reset());
describe('TOTP and storage crypto',()=>{
  const asciiBase32=(text:string)=>{let bits=0,value=0,out='';for(const x of new TextEncoder().encode(text)){value=(value<<8)|x;bits+=8;while(bits>=5){bits-=5;out+='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[(value>>>bits)&31];}}if(bits)out+='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[(value<<(5-bits))&31];return out;};
  it('matches all RFC 6238 test vectors for all three algorithms',async()=>{
    const times=[59,1111111109,1111111111,1234567890,2000000000,20000000000];
    const expected={SHA1:['94287082','07081804','14050471','89005924','69279037','65353130'],SHA256:['46119246','68084774','67062674','91819424','90698825','77737706'],SHA512:['90693936','25091201','99943326','93441116','38618901','47863826']};
    for(const [algorithm,secret] of [['SHA1','12345678901234567890'],['SHA256','12345678901234567890123456789012'],['SHA512','1234567890123456789012345678901234567890123456789012345678901234']]){
      const a=parseAccount({secret:asciiBase32(secret),label:'test',algorithm,digits:8});for(let i=0;i<times.length;i++)expect(await totp(a,times[i]*1000)).toBe(expected[algorithm as keyof typeof expected][i]);
    }
  });
  it('roundtrips authenticator URIs and rejects HOTP and malformed keys',()=>{const a=parseAccount({uri:'otpauth://totp/GitHub%3Ame%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub'});expect(parseAccount({uri:toURI(a)})).toEqual(a);expect(()=>parseAccount({uri:'otpauth://hotp/test?secret=JBSWY3DPEHPK3PXP'})).toThrow();expect(()=>base32('ABC!')).toThrow();expect(()=>base32('A')).toThrow();});
  it('authenticates ciphertext and binds it to its account ID',async()=>{const key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';const cipher=await encrypt({secret:'private'},key,'account:one');expect(cipher).not.toContain('private');expect(await decrypt(cipher,key,'account:one')).toEqual({secret:'private'});await expect(decrypt(cipher,key,'account:two')).rejects.toThrow();await expect(decrypt(cipher,'AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','account:one')).rejects.toThrow();});
});
describe('OpenSSH interoperability',()=>{
  for(const fixture of fixtures){it(`verifies real ssh-keygen ${fixture.kind} signatures and rejects altered messages`,async()=>{expect(await parseSSHKey(fixture.publicKey+'\n')).toHaveProperty('id');expect(await verifySSHSignature(fixture.publicKey,fixture.message,fixture.signature)).toBe(true);expect(await verifySSHSignature(fixture.publicKey,fixture.message+'tampered',fixture.signature)).toBe(false);expect(await verifySSHSignature(fixtures[(fixtures.indexOf(fixture)+1)%fixtures.length].publicKey,fixture.message,fixture.signature)).toBe(false);});}
  it('rejects malformed signature framing and unsupported public keys',async()=>{expect(await verifySSHSignature(fixtures[0].publicKey,fixtures[0].message,'garbage')).toBe(false);await expect(parseSSHKey('ssh-dss AAAA')).rejects.toThrow();});
});
describe('Worker API authorization',()=>{
  it('blocks unauthenticated vault data and cross-origin mutations',async()=>{expect((await req('accounts')).status).toBe(401);expect((await req('accounts/add',{},undefined,'https://evil.example')).status).toBe(403);const res=await req('status');expect(res.headers.get('cache-control')).toBe('no-store');expect(res.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");});
  it('requires the setup key and closes setup after registration',async()=>{expect((await req('setup/options',{setupKey:'wrong'})).status).toBe(403);await seed();expect((await req('setup/options',{setupKey:env.SETUP_KEY})).status).toBe(409);});
  it('stores encrypted accounts, returns codes without secrets, and requires recent auth for deletion',async()=>{const cookie=await seed();const added=await req('accounts/add',{issuer:'Test',label:'me',secret:'JBSWY3DPEHPK3PXP'},cookie);expect(added.status).toBe(200);const {id}=await added.json() as any;const listed=await req('accounts',undefined,cookie);const text=await listed.text();expect(text).toMatch(/"code":"\d{6}"/);expect(text).not.toContain('JBSWY3');const stored=await runInDurableObject(stub(),(_,ctx)=>ctx.storage.get('account:'+id));expect(String(stored)).not.toContain('JBSWY3');await runInDurableObject(stub(),async(_,ctx)=>{await ctx.storage.put('session:'+await hash('test-session'),{verified:Date.now()-180000,expires:Date.now()+900000});});expect((await req('accounts/delete',{id},cookie)).status).toBe(428);});
  it('refuses passkey deletion when it is the last key',async()=>{const cookie=await seed();expect((await req('passkeys/delete',{id:'test-credential'},cookie)).status).toBe(400);});
  it('expires sessions and invalidates them on logout',async()=>{const cookie=await seed();expect((await req('accounts',undefined,cookie)).status).toBe(200);await req('logout',{},cookie);expect((await req('accounts',undefined,cookie)).status).toBe(401);await seed();await runInDurableObject(stub(),async(_,ctx)=>{await ctx.storage.put('session:'+await hash('test-session'),{verified:0,expires:Date.now()-1});});expect((await req('accounts',undefined,cookie)).status).toBe(401);});
  it('rejects challenge replay and expiry',async()=>{await runInDurableObject(stub(),async(_,ctx)=>{await ctx.storage.put('challenge:'+await hash('expired'),{kind:'ssh',challenge:'expired',expires:Date.now()-1});});expect((await req('recovery/verify',{signature:'invalid'},'vault_challenge=expired')).status).toBe(400);expect((await req('recovery/verify',{signature:'invalid'},'vault_challenge=expired')).status).toBe(400);});
  it('limits authentication attempts',async()=>{for(let i=0;i<30;i++)expect((await req('auth/options',{})).status).toBe(409);expect((await req('auth/options',{})).status).toBe(429);});
});
async function ephemeralSSH(){
  const pair=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']) as CryptoKeyPair;
  const text=new TextEncoder();const join=(...parts:Uint8Array[])=>{const result=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let offset=0;for(const p of parts){result.set(p,offset);offset+=p.length;}return result;};
  const field=(p:Uint8Array|string)=>{const bytes=typeof p==='string'?text.encode(p):p,n=new Uint8Array(4);new DataView(n.buffer).setUint32(0,bytes.length);return join(n,bytes);};
  const blob=join(field('ssh-ed25519'),field(new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey))));const version=new Uint8Array([0,0,0,1]);
  return {publicKey:'ssh-ed25519 '+btoa(String.fromCharCode(...blob)),sign:async(message:string,namespace=SSH_NAMESPACE)=>{
    const digest=new Uint8Array(await crypto.subtle.digest('SHA-512',text.encode(message))),signed=join(text.encode('SSHSIG'),field(namespace),field(''),field('sha512'),field(digest));
    const signature=new Uint8Array(await crypto.subtle.sign('Ed25519',pair.privateKey,signed));const envelope=join(text.encode('SSHSIG'),version,field(blob),field(namespace),field(''),field('sha512'),field(join(field('ssh-ed25519'),field(signature))));
    return '-----BEGIN SSH SIGNATURE-----\n'+btoa(String.fromCharCode(...envelope))+'\n-----END SSH SIGNATURE-----\n';
  }};
}
describe('SSH recovery lifecycle',()=>{
  it('registers public keys behind auth, signs in using a one-time signature, and revokes old sessions',async()=>{
    const key=await ephemeralSSH();expect((await req('ssh-keys/add',{publicKey:key.publicKey})).status).toBe(401);const session=await seed();expect((await req('ssh-keys/add',{publicKey:key.publicKey,name:'Laptop'},session)).status).toBe(200);
    const options=await req('recovery/options',{publicKey:key.publicKey});expect(options.status).toBe(200);const {challenge}=await options.json() as any;expect(challenge).toContain(origin);const cookie=options.headers.get('set-cookie')!.split(';')[0];
    const signature=await key.sign(challenge);const verify=await req('recovery/verify',{signature},cookie);expect(verify.status).toBe(200);const recovered=verify.headers.get('set-cookie')!.split(';')[0];expect((await req('accounts',undefined,recovered)).status).toBe(200);expect((await req('accounts',undefined,session)).status).toBe(401);expect((await req('recovery/verify',{signature},cookie)).status).toBe(400);
    // A recovered owner can register a replacement passkey immediately.
    expect((await req('passkeys/options',{name:'Replacement'},recovered)).status).toBe(200);
  });
  it('rejects signatures for another namespace and revoked keys',async()=>{const key=await ephemeralSSH(),session=await seed();await req('ssh-keys/add',{publicKey:key.publicKey},session);const options=await req('recovery/options',{publicKey:key.publicKey});const {challenge}=await options.json() as any;const cookie=options.headers.get('set-cookie')!.split(';')[0];expect((await req('recovery/verify',{signature:await key.sign(challenge,'other-service')},cookie)).status).toBe(403);const parsed=await parseSSHKey(key.publicKey);await req('ssh-keys/delete',{id:parsed.id},session);expect((await req('recovery/options',{publicKey:key.publicKey})).status).toBe(403);});
});
