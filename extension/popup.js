for (const action of ['attach','detach']) document.getElementById(action).onclick=async()=>{
 const r=await chrome.runtime.sendMessage({action});document.getElementById('status').textContent=r.error||'Provider '+(action==='attach'?'enabled':'disabled');
};
