// Isolated-world bridge, injected only on the pinned vault approval page.
window.addEventListener('message', async event => {
 if(event.source!==window || event.origin!==location.origin || event.data?.channel!=='vault-provider-page')return;
 const {action,response}=event.data;
 if(!['request','complete','cancel'].includes(action))return;
 try {
   const result=await chrome.runtime.sendMessage({action,response});
   window.postMessage({channel:'vault-provider-extension',action,...result},location.origin);
 } catch(e) {window.postMessage({channel:'vault-provider-extension',action,error:e.message},location.origin);}
});
