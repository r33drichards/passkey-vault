import { b64, unb64 } from './crypto';
const encoder=new TextEncoder(), decoder=new TextDecoder();
export const SSH_NAMESPACE='passkey-vault';
export type SSHKey={id:string;name:string;publicKey:string;created:number};
class Reader {
  offset=0; constructor(public bytes:Uint8Array){}
  read(n:number):Uint8Array{if(n<0 || this.offset+n>this.bytes.length)throw new Error('Truncated SSH data');const result=this.bytes.slice(this.offset,this.offset+n);this.offset+=n;return result;}
  uint():number{return new DataView(this.read(4).buffer).getUint32(0);}
  string():Uint8Array{return this.read(this.uint());}
  text():string{return decoder.decode(this.string());}
  end(){if(this.offset!==this.bytes.length)throw new Error('Unexpected SSH data');}
}
function concat(...items:Uint8Array[]):Uint8Array{const out=new Uint8Array(items.reduce((n,x)=>n+x.length,0));let offset=0;for(const item of items){out.set(item,offset);offset+=item.length;}return out;}
function field(value:Uint8Array|string):Uint8Array{const bytes=typeof value==='string'?encoder.encode(value):value;const n=new Uint8Array(4);new DataView(n.buffer).setUint32(0,bytes.length);return concat(n,bytes);}
function mpint(bytes:Uint8Array):Uint8Array{if(!bytes.length || bytes[0]&128)throw new Error('Invalid SSH integer');while(bytes.length>1 && bytes[0]===0)bytes=bytes.slice(1);return bytes;}
const curves={nistp256:{name:'P-256',hash:'SHA-256',size:32},nistp384:{name:'P-384',hash:'SHA-384',size:48},nistp521:{name:'P-521',hash:'SHA-512',size:66}} as const;
function parsePublic(blob:Uint8Array){const r=new Reader(blob),type=r.text();let result;
  if(type==='ssh-ed25519'){const key=r.string();if(key.length!==32)throw new Error('Invalid Ed25519 key');result={type,key};}
  else if(type==='ssh-rsa'){const e=mpint(r.string()),n=mpint(r.string());if(n.length<256 || n.length>1024)throw new Error('Use an RSA key of 2048–8192 bits');result={type,e,n};}
  else if(type.startsWith('ecdsa-sha2-')){const curve=r.text();if(!(curve in curves)||type!==`ecdsa-sha2-${curve}`)throw new Error('Unsupported SSH curve');const key=r.string(),params=curves[curve as keyof typeof curves];if(key.length!==1+2*params.size||key[0]!==4)throw new Error('Invalid ECDSA key');result={type,key,curve};}
  else throw new Error('Use an Ed25519, RSA, or ECDSA public key (not an SSH certificate or FIDO sk- key)');
  r.end();return result;
}
export async function parseSSHKey(line:string):Promise<{id:string;publicKey:string}> {
  line=line.trim();const parts=line.split(/\s+/);if(parts.length<2||line.includes('\n')||line.includes('\r'))throw new Error('Paste one OpenSSH public key line');const blob=unb64(parts[1]);const key=parsePublic(blob);if(key.type!==parts[0])throw new Error('SSH key type mismatch');
  // Import now to reject malformed curve points and invalid RSA parameters at registration.
  if(key.type==='ssh-ed25519')await crypto.subtle.importKey('raw',key.key as BufferSource,'Ed25519',false,['verify']);
  else if(key.type==='ssh-rsa')await crypto.subtle.importKey('jwk',{kty:'RSA',n:b64(key.n!),e:b64(key.e!),ext:true},{name:'RSASSA-PKCS1-v1_5',hash:'SHA-512'},false,['verify']);
  else await crypto.subtle.importKey('raw',key.key as BufferSource,{name:'ECDSA',namedCurve:curves[key.curve as keyof typeof curves].name},false,['verify']);
  const fingerprint=b64(new Uint8Array(await crypto.subtle.digest('SHA-256',blob as BufferSource))).replaceAll('-','+').replaceAll('_','/');return {id:`SHA256:${fingerprint}`,publicKey:`${parts[0]} ${btoa(String.fromCharCode(...blob))}`};
}
export async function verifySSHSignature(publicKey:string,message:string,armored:string):Promise<boolean> {
  try {
    if(armored.length>12000)return false;
    const match=/^-----BEGIN SSH SIGNATURE-----\r?\n([A-Za-z0-9+/=\r\n]+)\r?\n-----END SSH SIGNATURE-----\s*$/.exec(armored.trim());if(!match)return false;
    const r=new Reader(unb64(match[1].replace(/\s/g,'')));if(decoder.decode(r.read(6))!=='SSHSIG'||r.uint()!==1)return false;
    const blob=r.string(),registered=unb64(publicKey.split(' ')[1]);if(b64(blob)!==b64(registered))return false;
    const namespace=r.text(),reserved=r.string(),hashAlg=r.text(),signatureReader=new Reader(r.string());r.end();
    if(namespace!==SSH_NAMESPACE||!['sha256','sha512'].includes(hashAlg))return false;
    const sigType=signatureReader.text(),signature=signatureReader.string();signatureReader.end();
    const digest=new Uint8Array(await crypto.subtle.digest(hashAlg==='sha512'?'SHA-512':'SHA-256',encoder.encode(message)));
    const signed=concat(encoder.encode('SSHSIG'),field(namespace),field(reserved),field(hashAlg),field(digest));const key=parsePublic(blob);
    if(key.type==='ssh-ed25519'){if(sigType!==key.type||signature.length!==64)return false;const k=await crypto.subtle.importKey('raw',key.key as BufferSource,'Ed25519',false,['verify']);return crypto.subtle.verify('Ed25519',k,signature as BufferSource,signed as BufferSource);}
    if(key.type==='ssh-rsa'){if(!['rsa-sha2-256','rsa-sha2-512'].includes(sigType))return false;const k=await crypto.subtle.importKey('jwk',{kty:'RSA',n:b64(key.n!),e:b64(key.e!),ext:true},{name:'RSASSA-PKCS1-v1_5',hash:sigType==='rsa-sha2-512'?'SHA-512':'SHA-256'},false,['verify']);return crypto.subtle.verify('RSASSA-PKCS1-v1_5',k,signature as BufferSource,signed as BufferSource);}
    if(sigType!==key.type)return false;const params=curves[key.curve as keyof typeof curves],sig=new Reader(signature),rs=[mpint(sig.string()),mpint(sig.string())];sig.end();if(rs.some(x=>x.length>params.size))return false;
    const raw=new Uint8Array(params.size*2);rs.forEach((x,i)=>raw.set(x,(i+1)*params.size-x.length));const k=await crypto.subtle.importKey('raw',key.key as BufferSource,{name:'ECDSA',namedCurve:params.name},false,['verify']);return crypto.subtle.verify({name:'ECDSA',hash:params.hash},k,raw,signed as BufferSource);
  }catch{return false;}
}
