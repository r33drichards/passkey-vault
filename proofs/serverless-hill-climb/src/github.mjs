import {SignJWT, importPKCS8} from 'jose';
const enc=new TextEncoder();
const response=(body,status=200)=>Response.json(body,{status,headers:{'Cache-Control':'no-store'}});
const triggerLabel=name=>name==='hill climb'||name==='hillclimb';
export const ACK='Ack — received the hill-climb request. This slice only acknowledges the request; no code changes or hill-climbing have started.\n\n<!-- serverless-hill-climb:ack:v1 -->';
export async function validSignature(secret,raw,signature){
  if(!/^sha256=[a-f0-9]{64}$/.test(signature || '')) return false;
  const key=await crypto.subtle.importKey('raw',enc.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['verify']);
  const bytes=Uint8Array.from(signature.slice(7).match(/../g),x=>parseInt(x,16));
  return crypto.subtle.verify('HMAC',key,bytes,raw);
}
export async function githubEvent(a,r){
  if(r.method!=='POST') return response({error:'method'},405);
  const app=await a.read('github-app');
  if(!app?.webhookSecret) return response({error:'app_setup_required'},503);
  const chunks=[];let size=0;const reader=r.body?.getReader();
  if(!reader)return response({error:'signature'},401);
  for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>1024*1024){await reader.cancel();return response({error:'size'},413);}chunks.push(value);}
  const raw=new Uint8Array(size);let pos=0;for(const v of chunks){raw.set(v,pos);pos+=v.length;}
  if(!await validSignature(app.webhookSecret,raw,r.headers.get('X-Hub-Signature-256')))return response({error:'signature'},401);
  let p;try{p=JSON.parse(new TextDecoder().decode(raw));}catch{return response({error:'json'},400);}
  const event=r.headers.get('X-GitHub-Event');
  if(event==='ping')return response({status:'pong'});
  if(event!=='pull_request'||p.action!=='labeled'||!triggerLabel(p.label?.name)||p.pull_request?.state!=='open')return response({status:'ignored'});
  const repo=p.repository,number=p.number,installation=p.installation?.id;
  if(String(repo?.owner?.id)!==a.env.GITHUB_OWNER_ID || String(p.pull_request?.base?.repo?.id)!==String(repo?.id))return response({error:'owner'},403);
  if(!Number.isSafeInteger(repo.id)||!Number.isSafeInteger(number)||number<1||!Number.isSafeInteger(installation)||!/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(repo.full_name||''))return response({error:'payload'},400);
  const delivery=r.headers.get('X-GitHub-Delivery');if(!/^[a-zA-Z0-9-]{1,100}$/.test(delivery||''))return response({error:'delivery'},400);
  const key=`gh:${repo.id}:${number}`,prior=await a.read(key);
  // Stable PR identity also deduplicates relabeling and redelivery with a new ID.
  if(prior){if(prior.status==='queued')await a.storage.setAlarm(a.now()+100);return response({status:prior.status,duplicate:true});}
  const queue=await a.storage.get('gh-queue')||[];
  const count=await a.storage.get('gh-count')||0;
  if(queue.length>=50||count>=5000)return response({error:'capacity'},429);
  const job={key,repo:repo.full_name,repoId:repo.id,number,installation,delivery,status:'queued',attempts:0};
  // Arm recovery before durable admission; alarm cannot execute during serial admission.
  await a.storage.setAlarm(a.now()+100);
  await a.storage.put('gh-queue',[...queue,key]);
  await a.save(key,job);await a.storage.put('gh-count',count+1);await a.save('gh-last',job);
  return response({status:'queued',duplicate:false},202);
}
// GitHub manifests return PKCS#1. Wrap its DER in PKCS#8 for WebCrypto,
// avoiding runtime-specific native crypto and never writing the PEM to disk.
export function pkcs8(pem){
  if(pem.includes('BEGIN PRIVATE KEY'))return pem;
  if(!pem.includes('BEGIN RSA PRIVATE KEY'))throw Error('key-format');
  const der=Uint8Array.from(atob(pem.replace(/-----[^-]+-----/g,'').replace(/\s/g,'')),c=>c.charCodeAt(0));
  const concat=(...xs)=>Uint8Array.from(xs.flatMap(x=>Array.from(x)));
  const length=n=>n<128?[n]:n<256?[129,n]:[130,n>>8,n&255];
  const octet=concat([4,...length(der.length)],der);
  const body=concat([2,1,0,48,13,6,9,42,134,72,134,247,13,1,1,1,5,0],octet);
  const all=concat([48,...length(body.length)],body);
  return '-----BEGIN PRIVATE KEY-----\n'+btoa(String.fromCharCode(...all))+'\n-----END PRIVATE KEY-----';
}
export async function githubAlarm(a){
  const queue=await a.storage.get('gh-queue')||[];if(!queue.length)return false;
  const key=queue[0],job=await a.read(key);await a.storage.setAlarm(a.now()+60000);
  if(!job){await a.storage.put('gh-queue',queue.slice(1));return true;}
  if(job.status==='posting'){
    // A crash after POST might have created a comment: never blindly repeat it.
    job.status='uncertain';job.reason='comment-outcome-requires-inspection';
  }else if(job.status==='queued'){
    job.attempts++;await a.save(key,job);
    try{
      const app=await a.read('github-app');
      const signing=await importPKCS8(pkcs8(app.privateKey),'RS256');
      const jwt=await new SignJWT({}).setProtectedHeader({alg:'RS256'}).setIssuer(String(app.id)).setIssuedAt(Math.floor(a.now()/1000)-60).setExpirationTime(Math.floor(a.now()/1000)+300).sign(signing);
      const appHeaders={Authorization:'Bearer '+jwt,'X-GitHub-Api-Version':'2022-11-28'};
      const inst=await a.json(`https://api.github.com/app/installations/${job.installation}`,{headers:appHeaders});
      if(String(inst.account?.id)!==a.env.GITHUB_OWNER_ID||String(inst.app_id)!==String(app.id))throw Error('installation-owner');
      const grant=await a.json(`https://api.github.com/app/installations/${job.installation}/access_tokens`,{method:'POST',headers:{...appHeaders,'Content-Type':'application/json'},body:JSON.stringify({repository_ids:[job.repoId],permissions:{pull_requests:'write'}})});
      if(!grant.token)throw Error('installation-token');
      const headers={Authorization:'Bearer '+grant.token,'X-GitHub-Api-Version':'2022-11-28','Content-Type':'application/json'};
      const pr=await a.json(`https://api.github.com/repos/${job.repo}/pulls/${job.number}`,{headers});
      if(pr.state!=='open'||!pr.labels?.some(x=>triggerLabel(x.name))){job.status='skipped';}
      else{
        job.status='posting';await a.save(key,job); // side-effect intent checkpoint
        const comment=await a.json(`https://api.github.com/repos/${job.repo}/issues/${job.number}/comments`,{method:'POST',headers,body:JSON.stringify({body:ACK})});
        if(!comment.id)throw Error('comment-response');
        job.status='completed';job.commentId=comment.id;
      }
    }catch{
      job.status=job.status==='posting'?'uncertain':job.attempts<3?'queued':'failed';
      job.reason=job.status==='uncertain'?'comment-outcome-requires-inspection':'github-request-failed';
    }
  }
  await a.save(key,job);await a.save('gh-last',job);
  if(job.status!=='queued')await a.storage.put('gh-queue',queue.slice(1));
  if(job.status==='queued'||queue.length>1)await a.storage.setAlarm(a.now()+10000);
  else if(!await a.storage.get('active-run'))await a.storage.deleteAlarm();
  return true;
}
