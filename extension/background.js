// A development-only proxy. No keys or vault session cookies enter the extension.
const api = chrome.webAuthenticationProxy;
const VAULT = 'https://passkey-vault.rwendt1337.workers.dev';
// Tests replace VAULT in a disposable copy, never in the installed production profile.
const pageURL = VAULT + '/provider';
const finish = (kind, value) => kind === 'create' ? api.completeCreateRequest(value) : api.completeGetRequest(value);
const reject = (kind, requestId, message) => finish(kind, {requestId, error:{name:'NotAllowedError',message}}).catch(()=>{});
async function begin(kind, event) {
  try {
    const {pending}=await chrome.storage.session.get('pending');
    if(pending) return reject(kind,event.requestId,'Another approval is pending');
    const options=JSON.parse(event.requestDetailsJson);
    const source=options.extensions?.remoteDesktopClientOverride;
    if(!source?.origin || source.sameOriginWithAncestors!==true)throw Error('Verified top-level origin required');
    if(new URL(source.origin).origin===VAULT)throw Error('Disable the provider before using a vault login passkey; SSH login remains available');
    // Reserve before opening the page; no request details in the URL or history.
    const [requestingTab]=await chrome.tabs.query({active:true,lastFocusedWindow:true});
    await chrome.storage.session.set({pending:{kind,requestId:event.requestId,options,returnTabId:requestingTab?.id}});
    const tab=await chrome.tabs.create({url:pageURL});
    const current=(await chrome.storage.session.get('pending')).pending;
    if(current?.requestId===event.requestId)await chrome.storage.session.set({pending:{...current,tabId:tab.id}});
    else await chrome.tabs.remove(tab.id);
  } catch(e) { await chrome.storage.session.remove('pending');await reject(kind,event.requestId,e.message); }
}
// Serialize startup so simultaneous requests cannot both reserve the single slot.
let starting=Promise.resolve();
api.onCreateRequest.addListener(r => {starting=starting.then(()=>begin('create',r));});
api.onGetRequest.addListener(r => {starting=starting.then(()=>begin('get',r));});
api.onIsUvpaaRequest.addListener(r => api.completeIsUvpaaRequest({requestId:r.requestId,isUvpaa:false}));
api.onRequestCanceled.addListener(async requestId=>{
  const {pending}=await chrome.storage.session.get('pending');
  if(pending?.requestId!==requestId)return;
  await chrome.storage.session.remove('pending');
  if(pending.tabId)await chrome.tabs.remove(pending.tabId).catch(()=>{});
});
chrome.tabs.onRemoved.addListener(async tabId=>{
 const {pending}=await chrome.storage.session.get('pending');
 if(pending?.tabId!==tabId)return;
 await chrome.storage.session.remove('pending');await reject(pending.kind,pending.requestId,'Approval closed');
});
chrome.runtime.onMessage.addListener((m, sender, reply) => {
  (async()=>{
    if(sender.id!==chrome.runtime.id)throw Error('Unknown sender');
    if(['attach','detach'].includes(m.action)) {
      if(sender.url!==chrome.runtime.getURL('popup.html'))throw Error('Use the extension popup');
      await api[m.action]();
      if(m.action==='detach')await chrome.storage.session.remove('pending');
      return {ok:true};
    }
    const {pending}=await chrome.storage.session.get('pending');
    if(sender.url!==pageURL || sender.frameId!==0 || !pending || pending.tabId!==sender.tab?.id)throw Error('No request for this approval tab');
    if(m.action==='request')return {request:{kind:pending.kind,options:pending.options}};
    if(m.action==='complete' || m.action==='cancel') {
      await chrome.storage.session.remove('pending');
      if(m.action==='cancel')await reject(pending.kind,pending.requestId,'Owner canceled');
      else {try {if(pending.returnTabId)await chrome.tabs.update(pending.returnTabId,{active:true});await finish(pending.kind,{requestId:pending.requestId,responseJson:JSON.stringify(m.response)});}catch(e){await reject(pending.kind,pending.requestId,'Provider response rejected');throw e;}}
      return {ok:true};
    }
    throw Error('Unknown action');
  })().then(reply,e=>reply({error:e.message}));
  return true;
});
