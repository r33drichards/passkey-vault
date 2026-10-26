import { createPasskey, signPasskey, validateRequest, type ProviderRequest, type StoredPasskey } from './provider';
import { randomToken, hash, encrypt, decrypt } from './crypto';
import { verifySSHSignature, SSH_NAMESPACE, type SSHKey } from './ssh';

type Pending = { session: string; expires: number; request: ProviderRequest; keyId: string; credentialId?: string; challenge: string };
export class ProviderError extends Error { constructor(public status: number, message: string) { super(message); } }
export async function providerRoute(path: string, body: Record<string,unknown>, session: string, storage: DurableObjectStorage, env: { VAULT_KEY: string; APP_ORIGIN: string; PROVIDER_ORIGINS?: string }) {
  const origins=(env.PROVIDER_ORIGINS || '').split(',').map(s=>s.trim()).filter(Boolean);
  if(!origins.length)throw new ProviderError(403,'Credential provider is not enabled');
  const keys=await storage.get<SSHKey[]>('sshKeys')||[];
  const read=async()=>Promise.all([...(await storage.list<string>({prefix:'site-key:'})).entries()].map(([id,cipher])=>decrypt<StoredPasskey>(cipher,env.VAULT_KEY,id)));
  if(path==='/api/provider/prepare') {
    const request=body.request as ProviderRequest;
    let source;try{source=validateRequest(request,origins);}catch(e){throw new ProviderError(400,(e as Error).message);}
    const key=keys.find(k=>k.id===body.keyId);if(!key)throw new ProviderError(403,'Choose a registered SSH key');
    const entries=await read();
    let credential:StoredPasskey|undefined;
    if(request.kind==='get') {
      credential=entries.find(k=>k.id===body.credentialId && k.rpId===source.rpId && (!request.options.allowCredentials?.length||request.options.allowCredentials.some((a:any)=>a.id===k.id)));
      if(!credential)throw new ProviderError(404,'Select a matching credential');
    } else if(entries.length>=100)throw new ProviderError(400,'Maximum 100 site credentials');
    // One outstanding transaction per session. Replacing it invalidates the old signature.
    const id=randomToken(),expires=Date.now()+120000;
    const challenge=JSON.stringify({purpose:'Approve site credential '+request.kind,vault:env.APP_ORIGIN,origin:source.origin,rpId:source.rpId,user:credential?.userName||request.options.user.name,credentialId:credential?.id,requestHash:await hash(JSON.stringify(request)),session,nonce:id,expires:new Date(expires).toISOString()})+'\n';
    await storage.put('provider-pending:'+session,{session,expires,request,keyId:key.id,credentialId:credential?.id,challenge} satisfies Pending);
    return {id,challenge,namespace:SSH_NAMESPACE,expires};
  }
  if(path==='/api/provider/complete') {
    const slot='provider-pending:'+session,p=await storage.get<Pending>(slot);
    // Consume before signature verification, including invalid attempts.
    await storage.delete(slot);
    if(!p||p.expires<Date.now()||p.session!==session||JSON.parse(p.challenge).nonce!==body.id)throw new ProviderError(400,'Approval expired or already used');
    const key=keys.find(k=>k.id===p.keyId);
    if(!key||typeof body.signature!=='string'||!await verifySSHSignature(key.publicKey,p.challenge,body.signature))throw new ProviderError(403,'Invalid approval signature');
    const entries=await read();
    let result;
    try {
      if(p.request.kind==='create') {
        if(entries.length>=100)throw Error('Maximum 100 site credentials');
        result=await createPasskey(p.request,origins,entries);
      } else {
        const key=entries.find(k=>k.id===p.credentialId);if(!key)throw Error('Credential deleted');
        result=await signPasskey(p.request,origins,key);
      }
    }catch(e){throw new ProviderError(400,(e as Error).message);}
    const storageId='site-key:'+result.stored.id;
    await storage.put(storageId,await encrypt(result.stored,env.VAULT_KEY,storageId));
    return {response:result.response};
  }
  if(path==='/api/provider/list')return {keys:keys.map(k=>({id:k.id,name:k.name})),credentials:(await read()).map(({id,rpId,userName,created})=>({id,rpId,userName,created}))};
  if(path==='/api/provider/cancel'){await storage.delete('provider-pending:'+session);return {ok:true};}
  throw new ProviderError(404,'Not found');
}
