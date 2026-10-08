import { startRegistration, startAuthentication, browserSupportsWebAuthn } from '@simplewebauthn/browser';
import { parseBitwarden, type PasswordEntry } from '../src/passwords';
import { QRScanner } from './qr';
import { bindQRImageTransfer } from './qr-transfer';
type Account = { id:string;issuer:string;label:string;digits:number;period:number;code:string };
const el=<T extends HTMLElement=HTMLElement>(id:string)=>document.getElementById(id) as T;
const input=(id:string)=>(el<HTMLInputElement>(id)).value;
const dialog=(id:string)=>el<HTMLDialogElement>(id);
let accounts:Account[]=[], serverOffset=0, loadedAt=0, signedIn=false, epoch=0, refreshing=false, lastAction=Date.now(), toastTimer:ReturnType<typeof setTimeout>;
const qr = new QRScanner(el<HTMLVideoElement>('qr-video'), el('qr-camera'), (text, error=false) => {
  el('qr-status').textContent=text;el('qr-status').hidden=false;el('qr-status').classList.toggle('qr-error',error);
}, (uri, account) => {
  el<HTMLTextAreaElement>('uri').value=uri;el('manual').hidden=true;
  el('qr-issuer').textContent=account.issuer || 'TOTP account';el('qr-label').textContent=account.label;el('qr-account').hidden=false;
});
el('scan-qr').addEventListener('click',()=>void qr.camera());
el('stop-qr').addEventListener('click',()=>{qr.stop();el('qr-status').textContent='Camera stopped.';});
bindQRImageTransfer(document, dialog('account-dialog'), el('qr-drop-zone'), file=>{void qr.image(file);}, message=>{el('qr-status').textContent=message;el('qr-status').hidden=false;el('qr-status').classList.add('qr-error');});
el('qr-drop-zone').addEventListener('click',()=>{qr.stop();el<HTMLInputElement>('qr-file').click();});
el('upload-qr').addEventListener('click',()=>{qr.stop();el<HTMLInputElement>('qr-file').click();});
el<HTMLInputElement>('qr-file').addEventListener('change',e=>{const file=(e.currentTarget as HTMLInputElement).files?.[0];if(file)void qr.image(file);el<HTMLInputElement>('qr-file').value='';});
dialog('account-dialog').addEventListener('close',()=>{qr.stop();el('qr-status').hidden=true;el('qr-account').hidden=true;});
document.addEventListener('visibilitychange',()=>{if(document.hidden){qr.stop();}});
window.addEventListener('pagehide',()=>qr.stop());
class ApiError extends Error {constructor(message:string,public status:number){super(message);}}
async function api(path:string, body?:unknown):Promise<any> {
  const res=await fetch('/api/'+path,{method:body===undefined?'GET':'POST',credentials:'same-origin',headers:body===undefined?{}:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),cache:'no-store'});
  let data;try{data=await res.json();}catch{throw new Error('Unable to reach the vault');}
  if(!res.ok){if(res.status===401)showLocked(true);throw new ApiError(data.error||'Request failed',res.status);}return data;
}
function toast(message:string,error=false){clearTimeout(toastTimer);el('toast').textContent=message;el('toast').classList.toggle('error',error);el('toast').hidden=false;toastTimer=setTimeout(()=>{el('toast').hidden=true;},5000);}
async function action(button:HTMLButtonElement,fn:()=>Promise<void>){button.disabled=true;try{await fn();}catch(e){toast((e as Error).message||'Action failed',true);}finally{button.disabled=false;}}
function showLocked(initialized:boolean){qr.stop();epoch++;signedIn=false;accounts=[];passwordEntries=[];el('passwords').replaceChildren();el<HTMLFormElement>('password-form').reset();clearImport();el('accounts').replaceChildren();el('passkeys').replaceChildren();for(const d of document.querySelectorAll('dialog'))d.close();el<HTMLFormElement>('account-form').reset();el<HTMLFormElement>('setup-form').reset();el('vault').hidden=true;el('gate').hidden=false;el('loading').hidden=true;el('lock').hidden=true;el('setup-form').hidden=initialized;el('sign-in').hidden=!initialized;el('recover').hidden=!initialized;el('gate-title').textContent=initialized?'Unlock your vault':'Welcome to your vault';el('gate-description').textContent=initialized?'Use your passkey to access your accounts.':'Use your one-time setup key to register the first passkey.';}
async function login(){const {options}=await api('auth/options',{});const response=await startAuthentication({optionsJSON:options});await api('auth/verify',{response});lastAction=Date.now();}
async function unlock(){epoch++;signedIn=true;el('gate').hidden=true;el('vault').hidden=false;el('lock').hidden=false;el('loading').hidden=true;await refresh();await refreshPasswords();}
async function refresh(){if(!signedIn||refreshing)return;refreshing=true;const myEpoch=epoch;try{const data=await api('accounts');if(myEpoch!==epoch)return;accounts=data.accounts;serverOffset=data.now-Date.now();loadedAt=data.now;render();}finally{refreshing=false;}}
function node(tag:string,className:string,text?:string){const n=document.createElement(tag);n.className=className;if(text!==undefined)n.textContent=text;return n;}
function render(){const term=input('search').toLowerCase();const filtered=accounts.filter(a=>(a.issuer+' '+a.label).toLowerCase().includes(term));el('accounts').replaceChildren();el('count').textContent=String(accounts.length);el('empty').hidden=accounts.length>0;
  for(const a of filtered){const card=node('article','card');const top=node('div','card-top');top.append(node('div','avatar',(a.issuer||a.label).slice(0,1).toUpperCase()));const title=node('div','account-text');title.append(node('div','account-name',a.issuer||a.label),node('div','account-label',a.issuer?a.label:'TOTP account'));top.append(title);const remove=node('button','remove','×') as HTMLButtonElement;remove.setAttribute('aria-label',`Remove ${a.issuer||a.label}`);remove.addEventListener('click',()=>action(remove,async()=>{if(!await confirmRemoval('Remove account?',`Remove ${a.issuer||a.label} from this vault? Make sure you have its setup key saved elsewhere.`))return;await recent(()=>api('accounts/delete',{id:a.id}));await refresh();}));top.append(remove);card.append(top);
    const code=node('button','code') as HTMLButtonElement;const numbers=node('span','numbers',a.code.slice(0,a.digits/2)+' '+a.code.slice(a.digits/2));code.append(numbers,node('span','copy-label','COPY'));code.setAttribute('aria-label',`Copy code for ${a.issuer||a.label}`);code.addEventListener('click',()=>action(code,async()=>{if(!isCurrent(a))throw new Error('Code is refreshing. Try again');await navigator.clipboard.writeText(a.code);toast('Code copied');}));card.append(code);
    const progressWrap=node('div','progress'),progress=document.createElement('progress');progress.max=a.period;progress.setAttribute('aria-label','Time until next code');progressWrap.append(progress);card.append(progressWrap);const bottom=node('div','card-bottom');bottom.append(node('span','',`${a.digits}-digit code`),node('span','remaining'));card.append(bottom);card.dataset.id=a.id;el('accounts').append(card);
  }if(accounts.length && !filtered.length)el('accounts').append(node('p','muted','No matching accounts.'));tick();
}
function isCurrent(a:Account){const now=Date.now()+serverOffset;return signedIn && now>=loadedAt && Math.floor(now/1000/a.period)===Math.floor(loadedAt/1000/a.period);}
function tick(){if(!signedIn||document.hidden)return;const now=Date.now()+serverOffset;let stale=false;
  for(const card of el('accounts').querySelectorAll<HTMLElement>('.card')){const a=accounts.find(a=>a.id===card.dataset.id)!;const remaining=a.period-((now/1000)%a.period);(card.querySelector('progress') as HTMLProgressElement).value=remaining;card.querySelector('.remaining')!.textContent=`${Math.ceil(remaining)}s remaining`;const current=isCurrent(a);const button=card.querySelector<HTMLButtonElement>('.code')!;button.disabled=!current;if(!current){card.querySelector('.numbers')!.textContent='··· ···';stale=true;}}
  if(accounts.some(a=>!isCurrent(a)))stale=true;if(stale&&!refreshing)refresh().catch(e=>toast(e.message,true));
}
function confirmRemoval(title:string,message:string):Promise<boolean>{el('confirm-title').textContent=title;el('confirm-text').textContent=message;const d=dialog('confirm-dialog');d.returnValue='';d.showModal();return new Promise(resolve=>d.addEventListener('close',()=>resolve(d.returnValue==='yes'),{once:true}));}
async function recent(fn:()=>Promise<unknown>){try{return await fn();}catch(e){if(e instanceof ApiError && e.status===428){await login();return await fn();}throw e;}}
async function loadPasskeys(){const {passkeys}=await api('passkeys');el('passkeys').replaceChildren();for(const p of passkeys){const row=node('div','key-row'),label=node('div','',p.name);label.append(node('small','',`Added ${new Date(p.created).toLocaleDateString()}`));row.append(label);if(passkeys.length>1){const remove=node('button','quiet','Remove') as HTMLButtonElement;remove.addEventListener('click',()=>action(remove,async()=>{if(!await confirmRemoval('Remove passkey?',`Remove ${p.name}? All signed-in sessions will also be locked.`))return;await recent(()=>api('passkeys/delete',{id:p.id}));showLocked(true);}));row.append(remove);}el('passkeys').append(row);}}
el<HTMLButtonElement>('sign-in').addEventListener('click',e=>action(e.currentTarget as HTMLButtonElement,async()=>{if(!browserSupportsWebAuthn())throw new Error('This browser does not support passkeys');await login();await unlock();}));
el<HTMLFormElement>('setup-form').addEventListener('submit',e=>{e.preventDefault();action(el('setup-form').querySelector('button')!,async()=>{const {options}=await api('setup/options',{setupKey:input('setup-key'),name:input('setup-name')});el<HTMLInputElement>('setup-key').value='';const response=await startRegistration({optionsJSON:options});await api('setup/verify',{response});await unlock();toast('Your vault is ready. Add a backup passkey in settings.');});});
async function lock(){showLocked(true);try{await api('logout',{});}catch{toast('Could not end the server session. It expires within 15 minutes.',true);}}
el('lock').addEventListener('click',lock);
for(const id of ['add','empty-add'])el(id).addEventListener('click',()=>dialog('account-dialog').showModal());
for(const button of document.querySelectorAll<HTMLButtonElement>('[data-close]'))button.addEventListener('click',()=>{const d=dialog(button.dataset.close!);d.close();if(d.id==='account-dialog')el<HTMLFormElement>('account-form').reset();});
dialog('account-dialog').addEventListener('close',()=>el<HTMLFormElement>('account-form').reset());
el('uri').addEventListener('input',()=>{el('manual').hidden=Boolean(input('uri').trim());el('qr-account').hidden=true;el('qr-status').hidden=true;});dialog('account-dialog').addEventListener('close',()=>{el('manual').hidden=false;});
el<HTMLFormElement>('account-form').addEventListener('submit',e=>{e.preventDefault();action(el('account-form').querySelector('button[type=submit]')!,async()=>{await api('accounts/add',{uri:input('uri'),issuer:input('issuer'),label:input('label'),secret:input('secret'),algorithm:input('algorithm'),digits:Number(input('digits')),period:Number(input('period'))});dialog('account-dialog').close();await refresh();toast('Account added');});});
el('search').addEventListener('input',()=>{render();renderPasswords();});
el<HTMLButtonElement>('settings').addEventListener('click',e=>action(e.currentTarget as HTMLButtonElement,async()=>{await loadPasskeys();await loadSSHKeys();dialog('settings-dialog').showModal();}));
el<HTMLFormElement>('passkey-form').addEventListener('submit',e=>{e.preventDefault();action(el('passkey-form').querySelector('button')!,async()=>{const {options}=await recent(()=>api('passkeys/options',{name:input('passkey-name')})) as any;const response=await startRegistration({optionsJSON:options});await api('passkeys/verify',{response});el<HTMLFormElement>('passkey-form').reset();await loadPasskeys();toast('Backup passkey added');});});
el<HTMLButtonElement>('export').addEventListener('click',e=>action(e.currentTarget as HTMLButtonElement,async()=>{await login();const data=await api('export',{});const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='passkey-vault-backup.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);toast('Backup downloaded. Keep this file private.');}));
let recoveryChallenge='';
function download(text:string,name:string,type='text/plain'){const url=URL.createObjectURL(new Blob([text],{type}));const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
async function loadSSHKeys(){const {keys}=await api('ssh-keys');el('ssh-keys').replaceChildren();for(const key of keys){const row=node('div','key-row'),label=node('div','',key.name);label.append(node('small','fingerprint',key.id));const remove=node('button','quiet','Remove') as HTMLButtonElement;remove.addEventListener('click',()=>action(remove,async()=>{if(!await confirmRemoval('Remove recovery key?',`Remove ${key.name}? All sessions will be locked.`))return;await recent(()=>api('ssh-keys/delete',{id:key.id}));showLocked(true);}));row.append(label,remove);el('ssh-keys').append(row);}}
el<HTMLFormElement>('ssh-form').addEventListener('submit',e=>{e.preventDefault();action(el('ssh-form').querySelector('button')!,async()=>{await recent(()=>api('ssh-keys/add',{publicKey:input('ssh-public'),name:input('ssh-name')}));el<HTMLFormElement>('ssh-form').reset();await loadSSHKeys();toast('SSH recovery key registered. Test it before relying on it.');});});
el('recover').addEventListener('click',()=>dialog('recovery-dialog').showModal());
dialog('recovery-dialog').addEventListener('close',()=>{recoveryChallenge='';el('recovery-sign').hidden=true;el<HTMLFormElement>('recovery-start').reset();el<HTMLFormElement>('recovery-finish').reset();});
el<HTMLFormElement>('recovery-start').addEventListener('submit',e=>{e.preventDefault();action(el('recovery-start').querySelector('button')!,async()=>{const data=await api('recovery/options',{publicKey:input('recovery-public')});recoveryChallenge=data.challenge;el('recovery-sign').hidden=false;el<HTMLTextAreaElement>('recovery-signature').value='';});});
el('download-challenge').addEventListener('click',()=>download(recoveryChallenge,'challenge.txt'));
el<HTMLFormElement>('recovery-finish').addEventListener('submit',e=>{e.preventDefault();action(el('recovery-finish').querySelector('button')!,async()=>{await api('recovery/verify',{signature:input('recovery-signature')});dialog('recovery-dialog').close();lastAction=Date.now();await unlock();toast('Recovered. You can now register a new passkey.');});});
el('confirm-cancel').addEventListener('click',()=>dialog('confirm-dialog').close('no'));el('confirm-ok').addEventListener('click',()=>dialog('confirm-dialog').close('yes'));
for(const event of ['pointerdown','keydown'])document.addEventListener(event,()=>{lastAction=Date.now();},{passive:true});
setInterval(()=>{if(signedIn && Date.now()-lastAction>600000){void lock();return;}tick();},500);
document.addEventListener('visibilitychange',()=>{if(signedIn&&!document.hidden){if(Date.now()-lastAction>600000)void lock();else {loadedAt=0;tick();}}});
async function init(){try{const state=await api('status');if(state.signedIn){lastAction=Date.now();await unlock();}else showLocked(state.initialized);}catch(e){el('loading').textContent=(e as Error).message;toast((e as Error).message,true);}}


type PasswordSummary = Pick<PasswordEntry,'name'|'username'|'urls'> & {id:string};
let passwordEntries:PasswordSummary[]=[];
let importExport:unknown;
function clearImport(){importRevision++;importExport=undefined;el<HTMLFormElement>('import-form').reset();el('import-preview').textContent='';el<HTMLButtonElement>('import-submit').disabled=true;}
async function refreshPasswords(){const current=epoch;const data=await api('passwords');if(current!==epoch || !signedIn)return;passwordEntries=data.entries;renderPasswords();}
function renderPasswords(){const term=input('search').toLowerCase();el('passwords').replaceChildren();el('password-count').textContent=String(passwordEntries.length);
  for(const entry of passwordEntries.filter(p=>(p.name+' '+p.username+' '+p.urls.join(' ')).toLowerCase().includes(term))){
    const card=node('article','card');card.append(node('h3','account-name',entry.name),node('p','account-label',entry.username),node('p','muted',entry.urls.join(' · ')));
    const buttons=node('div','actions');
    for(const [label,fn] of [
      ['Copy username',async()=>{await navigator.clipboard.writeText(entry.username);toast('Username copied');}],
      ['Copy password',async()=>{const current=epoch;const data=await recent(()=>api('passwords/read',{id:entry.id})) as any;if(current!==epoch || !signedIn)return;await navigator.clipboard.writeText(data.entry.password);toast('Password copied');}],
      ['Edit / reveal',async()=>{const current=epoch;const data=await recent(()=>api('passwords/read',{id:entry.id})) as any;if(current!==epoch || !signedIn)return;openPassword(data.entry);}],
      ['Delete',async()=>{if(!await confirmRemoval('Delete login?',`Delete ${entry.name}?`))return;await recent(()=>api('passwords/delete',{id:entry.id}));await refreshPasswords();}]
    ] as [string,()=>Promise<void>][]){const button=node('button','secondary',label) as HTMLButtonElement;button.addEventListener('click',()=>action(button,fn));buttons.append(button);}card.append(buttons);el('passwords').append(card);
  }
  if(!el('passwords').childElementCount)el('passwords').append(node('p','muted',passwordEntries.length?'No matching logins.':'Add a login or import from Bitwarden.'));
}
function openPassword(entry?:PasswordEntry & {id:string}){el<HTMLFormElement>('password-form').reset();el<HTMLInputElement>('password-value').type='password';el('password-toggle').textContent='Show password';if(entry){for(const [id,value] of Object.entries({'password-id':entry.id,'password-name':entry.name,'password-username':entry.username,'password-value':entry.password,'password-urls':entry.urls.join('\n'),'password-notes':entry.notes})){el<HTMLInputElement>(id).value=value;}}dialog('password-dialog').showModal();}
el('password-add').addEventListener('click',()=>openPassword());
dialog('password-dialog').addEventListener('close',()=>el<HTMLFormElement>('password-form').reset());
el('password-toggle').addEventListener('click',()=>{const field=el<HTMLInputElement>('password-value');field.type=field.type==='password'?'text':'password';el('password-toggle').textContent=field.type==='password'?'Show password':'Hide password';});
el('password-generate').addEventListener('click',()=>{const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';let value='';while(value.length<24){const bytes=crypto.getRandomValues(new Uint8Array(32));for(const b of bytes){if(b<Math.floor(256/alphabet.length)*alphabet.length && value.length<24)value+=alphabet[b%alphabet.length];}}el<HTMLInputElement>('password-value').value=value;});
el<HTMLFormElement>('password-form').addEventListener('submit',e=>{e.preventDefault();action(el('password-form').querySelector('button[type=submit]')!,async()=>{const body={...(input('password-id')?{id:input('password-id')}:{}),name:input('password-name'),username:input('password-username'),password:input('password-value'),urls:input('password-urls').split('\n').map(u=>u.trim()).filter(Boolean),notes:input('password-notes')};await recent(()=>api('passwords/save',body));dialog('password-dialog').close();await refreshPasswords();toast('Login saved');});});
el('bitwarden-import').addEventListener('click',()=>dialog('import-dialog').showModal());
dialog('import-dialog').addEventListener('close',clearImport);
let importRevision=0;
el<HTMLInputElement>('import-file').addEventListener('change',async()=>{const revision=++importRevision,current=epoch;importExport=undefined;el<HTMLButtonElement>('import-submit').disabled=true;try{const file=el<HTMLInputElement>('import-file').files?.[0];if(!file)return;if(file.size>1900000)throw new Error('Export must be smaller than 1.9 MB');const value=JSON.parse(await file.text());if(revision!==importRevision || current!==epoch || !dialog('import-dialog').open)return;const parsed=parseBitwarden(value);importExport=value;el('import-preview').textContent=`${parsed.entries.length} logins to import; ${parsed.skipped} unsupported items skipped; ${parsed.omitted} logins have additional fields that will be omitted.\nLogins: ${parsed.entries.slice(0,10).map(e=>e.name).join(", ")}${parsed.entries.length>10?" …":""}`;el<HTMLButtonElement>('import-submit').disabled=!parsed.entries.length;}catch(e){if(revision===importRevision && current===epoch && dialog('import-dialog').open)el('import-preview').textContent=(e as Error).message;}});
el<HTMLFormElement>('import-form').addEventListener('submit',e=>{e.preventDefault();action(el<HTMLButtonElement>('import-submit'),async()=>{if(!importExport)throw new Error('Choose an export first');const value=importExport;const result=await recent(()=>api('passwords/import',{export:value})) as any;dialog('import-dialog').close();await refreshPasswords();toast(`Imported ${result.imported} logins; skipped ${result.skipped} items`);});});

void init();
