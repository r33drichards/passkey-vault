export {};
const el=<T extends HTMLElement>(id:string)=>document.getElementById(id) as T;
const status=(s:string)=>{el('status').textContent=s;};
const bridge=(action:string,response?:unknown)=>window.postMessage({channel:'vault-provider-page',action,response},location.origin);
let request:any,approval:any,download:string|undefined,loading=false;
async function api(path:string,body:unknown){const r=await fetch('/api/provider/'+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const v=await r.json();if(!r.ok)throw Error(v.error||'Request failed');return v;}
const safely=(fn:()=>Promise<void>)=>{void fn().catch(e=>status(e.message));};
window.addEventListener('message',event=>{
 if(event.source!==window||event.origin!==location.origin||event.data?.channel!=='vault-provider-extension')return;
 const m=event.data;if(m.error){status(m.error);return;}
 if(m.action==='request') {
  if(loading)return;loading=true;
  request=m.request;
  const o=request.options;
  el('details').textContent=JSON.stringify({operation:request.kind,site:o.extensions.remoteDesktopClientOverride.origin,rpId:o.rp?.id||o.rpId,account:o.user?.name},null,2);
  void (async()=>{
   const data=await api('list',{}),keys=el<HTMLSelectElement>('key'),credentials=el<HTMLSelectElement>('credential');keys.replaceChildren();credentials.replaceChildren();
   for(const k of data.keys)keys.add(new Option(k.name,k.id));
   for(const c of data.credentials.filter((c:any)=>c.rpId===o.rpId&&(!o.allowCredentials?.length||o.allowCredentials.some((a:any)=>a.id===c.id))))credentials.add(new Option(c.userName,c.id));
   credentials.disabled=request.kind==='create';status('Review the site, then prepare a one-time approval.');
  })().catch(e=>{loading=false;status(e.message);});
 }else if(m.action==='complete') {status('Credential operation completed. Return to the requesting site.');el<HTMLButtonElement>('cancel').disabled=true;}
 else if(m.action==='cancel')status('Canceled. You may close this tab.');
});
el('load').onclick=()=>bridge('request');
el('prepare').onsubmit=e=>{e.preventDefault();safely(async()=>{
 if(!request)throw Error('Load a browser request first');
 approval=await api('prepare',{request,keyId:el<HTMLSelectElement>('key').value,credentialId:el<HTMLSelectElement>('credential').value});
 if(download)URL.revokeObjectURL(download);download=URL.createObjectURL(new Blob([approval.challenge],{type:'text/plain'}));
 el<HTMLAnchorElement>('download').href=download;el('challenge').textContent=approval.challenge;el('approval').hidden=false;
 status('Sign this exact challenge within two minutes.');
});};
el('complete').onsubmit=e=>{e.preventDefault();safely(async()=>{
 if(!approval)throw Error('Prepare an approval first');
 const id=approval.id;approval=undefined;el('approval').hidden=true;
 const result=await api('complete',{id,signature:el<HTMLTextAreaElement>('signature').value});el<HTMLTextAreaElement>('signature').value='';
 bridge('complete',result.response);
});};
el('cancel').onclick=()=>{safely(async()=>{await api('cancel',{});});bridge('cancel');};
bridge('request');
