// Software authenticator core. Call only after transaction-specific owner approval.
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { b64, unb64, randomToken } from './crypto';
export type StoredPasskey = {id:string;rpId:string;userId:string;userName:string;privateKey:JsonWebKey;counter:number;created:number};
export type ProviderRequest = {kind:'create'|'get';options:Record<string,any>};
const bytes=(s:string)=>new TextEncoder().encode(s);
const join=(...a:Uint8Array[])=>{const out=new Uint8Array(a.reduce((n,v)=>n+v.length,0));let i=0;for(const v of a){out.set(v,i);i+=v.length;}return out;};
const digest=async(a:Uint8Array)=>new Uint8Array(await crypto.subtle.digest('SHA-256',a as BufferSource));
export function validateRequest(request:ProviderRequest, allowedOrigins:string[]) {
  if(!request || !['create','get'].includes(request.kind))throw Error('Unsupported operation');
  const o=request.options, source=o?.extensions?.remoteDesktopClientOverride;
  if(!source || source.sameOriginWithAncestors!==true)throw Error('Browser origin required; cross-origin frames unsupported');
  const origin=new URL(source.origin);
  if(origin.origin!==source.origin || !allowedOrigins.includes(origin.origin))throw Error('Site not allowed');
  if(origin.protocol!=='https:' && !(origin.protocol==='http:'&&origin.hostname==='localhost'))throw Error('Secure origin required');
  if((request.kind==='create'?o.authenticatorSelection?.userVerification:o.userVerification)==='required')throw Error('SSH approval does not provide WebAuthn user verification');
  const rpId=request.kind==='create'?o.rp?.id:o.rpId;
  // Parent RP IDs require their own explicit configured origin, never arbitrary suffixes.
  if(typeof rpId!=='string'||!(rpId===origin.hostname||(origin.hostname.endsWith('.'+rpId)&&allowedOrigins.includes('https://'+rpId))))throw Error('RP ID is not explicitly allowed for this origin');
  if(typeof o.challenge!=='string'||!/^[A-Za-z0-9_-]{22,1024}$/.test(o.challenge))throw Error('Invalid challenge');
  for(const key of Object.keys(o.extensions||{}))if(!['remoteDesktopClientOverride','credProps'].includes(key))throw Error('Unsupported extension: '+key);
  if(request.kind==='create') {
    if(!o.pubKeyCredParams?.some((p:any)=>p.type==='public-key'&&p.alg===-7))throw Error('ES256 required');
    if(o.attestation && o.attestation!=='none')throw Error('Only none attestation supported');
    if(o.authenticatorSelection?.authenticatorAttachment==='platform')throw Error('Platform authenticator unsupported');
    if(typeof o.user?.id!=='string'||unb64(o.user.id).length<1||unb64(o.user.id).length>64)throw Error('Invalid user ID');
    if(typeof o.user?.name!=='string'||o.user.name.length>256)throw Error('Invalid username');
  }
  return {origin:origin.origin,rpId};
}
function clientData(request:ProviderRequest,origin:string){return bytes(JSON.stringify({type:request.kind==='create'?'webauthn.create':'webauthn.get',challenge:request.options.challenge,origin,crossOrigin:false}));}
async function authData(rpId:string,flags:number,counter:number,extra=new Uint8Array()){
 const n=new Uint8Array(4);new DataView(n.buffer).setUint32(0,counter);return join(await digest(bytes(rpId)),new Uint8Array([flags]),n,extra);
}
export async function createPasskey(request:ProviderRequest,origins:string[],existing:StoredPasskey[]) {
 const {origin,rpId}=validateRequest(request,origins),o=request.options;
 if(request.kind!=='create')throw Error('Expected registration');
 if(existing.some(k=>k.rpId===rpId&&o.excludeCredentials?.some((x:any)=>x.id===k.id)))throw Error('Credential excluded');
 const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']) as CryptoKeyPair;
 const pub=await crypto.subtle.exportKey('jwk',pair.publicKey) as JsonWebKey,id=randomToken(),rawId=unb64(id);
 const cose=isoCBOR.encode(new Map<number,number|Uint8Array>([[1,2],[3,-7],[-1,1],[-2,unb64(pub.x!)],[-3,unb64(pub.y!)]]));
 const len=new Uint8Array(2);new DataView(len.buffer).setUint16(0,rawId.length);
 // UP+AT only: an SSH signature is authorization, not WebAuthn UV.
 const data=await authData(rpId,0x41,0,join(new Uint8Array(16),len,rawId,cose));
 const stored:StoredPasskey={id,rpId,userId:o.user.id,userName:o.user.name,privateKey:await crypto.subtle.exportKey('jwk',pair.privateKey) as JsonWebKey,counter:0,created:Date.now()};
 return {stored,response:{id,rawId:id,type:'public-key',authenticatorAttachment:'cross-platform',clientExtensionResults:o.extensions?.credProps?{credProps:{rk:true}}:{},response:{publicKeyAlgorithm:-7,publicKey:b64(new Uint8Array(await crypto.subtle.exportKey('spki',pair.publicKey) as ArrayBuffer)),authenticatorData:b64(data),clientDataJSON:b64(clientData(request,origin)),attestationObject:b64(isoCBOR.encode(new Map<string,string|Map<string,string>|Uint8Array>([['fmt','none'],['attStmt',new Map()],['authData',data]]))),transports:[]}}};
}
function der(raw:Uint8Array){const ints=[raw.slice(0,32),raw.slice(32)].map(a=>{while(a.length>1&&a[0]===0)a=a.slice(1);if(a[0]&128)a=join(new Uint8Array([0]),a);return join(new Uint8Array([2,a.length]),a);});const b=join(...ints);return join(new Uint8Array([48,b.length]),b);}
export async function signPasskey(request:ProviderRequest,origins:string[],stored:StoredPasskey){
 const {origin,rpId}=validateRequest(request,origins),o=request.options;
 if(request.kind!=='get'||stored.rpId!==rpId)throw Error('Credential RP mismatch');
 if(o.allowCredentials?.length&&!o.allowCredentials.some((x:any)=>x.id===stored.id))throw Error('Credential not allowed');
 if(stored.counter>=0xffffffff)throw Error('Counter exhausted');
 const counter=stored.counter+1,data=await authData(rpId,1,counter),client=clientData(request,origin);
 const key=await crypto.subtle.importKey('jwk',stored.privateKey,{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
 const signature=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,join(data,await digest(client)) as BufferSource);
 return {stored:{...stored,counter},response:{id:stored.id,rawId:stored.id,type:'public-key',authenticatorAttachment:'cross-platform',clientExtensionResults:{},response:{clientDataJSON:b64(client),authenticatorData:b64(data),signature:b64(der(new Uint8Array(signature))),userHandle:stored.userId}}};
}
