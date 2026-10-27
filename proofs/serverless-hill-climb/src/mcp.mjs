export const LAMBDA_ENDPOINT='https://o27o445mvjsctrp4tryanmdste0pbjfi.lambda-url.us-east-1.on.aws/mcp';
export const TOKEN_ENDPOINT='https://keycloak-production-295b.up.railway.app/realms/pi-lambda/protocol/openid-connect/token';
// Direct MCP client. Lifecycle service sees only session/lease IDs, never code.
// No automatic retries: a lost tool response may represent a completed side effect.
export class NativeMcp {
  constructor(fetcher, lease) {
    const u=new URL(lease.url);
    if(u.protocol!=='https:' || u.username || u.password || u.search || u.hash || !(lease.transport==='lambda' ? u.href===LAMBDA_ENDPOINT : u.hostname.endsWith('.modal.host'))) throw Error('invalid-connect-url');
    if(typeof lease.token!=='string'||!lease.token||typeof lease.sandbox!=='string')throw Error('invalid-lease');
    this.fetcher=fetcher;this.lease=lease;this.sequence=0;
  }
  async rpc(method,params,notify=false) {
    const id=notify?undefined:++this.sequence;
    const token=this.getToken ? await this.getToken() : this.lease.token;
    if(this.lease.transport==='lambda') params={...params,_meta:{...params?._meta,'io.modelcontextprotocol/protocolVersion':this.protocol,'io.modelcontextprotocol/clientCapabilities':{}}};
    const headers={Authorization:'Bearer '+token,'Content-Type':'application/json',Accept:'application/json, text/event-stream','MCP-Protocol-Version':this.protocol || '2024-11-05'};
    if(this.lease.transport==='lambda'){headers['Mcp-Method']=method;if(params?.name)headers['Mcp-Name']=params.name;headers['X-MCP-Session-Id']=this.lease.session;}
    if(this.session)headers['Mcp-Session-Id']=this.session;
    const r=await this.fetcher(this.lease.url,{method:'POST',redirect:'manual',headers,body:JSON.stringify({jsonrpc:'2.0',...(notify?{}:{id}),method,...(params?{params}:{})}),signal:AbortSignal.timeout(45000)});
    if(!r.ok){await r.body?.cancel();throw Error('mcp-http-failed-no-replay');}
    const session=r.headers.get('Mcp-Session-Id');if(session)this.session=session;
    if(notify){await r.body?.cancel();return;}
    const reader=r.body?.getReader();if(!reader)throw Error('mcp-empty');
    const decoder=new TextDecoder();let total=0,buffer='';
    const sse=(r.headers.get('Content-Type')||'').includes('text/event-stream');
    const result=msg=>{if(msg?.jsonrpc!=='2.0'||msg.id!==id)return; if(msg.error)throw Error('mcp-protocol-error');if(!('result' in msg))throw Error('mcp-invalid-result');return {value:msg.result};};
    try {
      for(;;){
        const {value,done}=await reader.read();
        if(value){total+=value.length;if(total>65536)throw Error('mcp-output-limit');buffer+=decoder.decode(value,{stream:true});}
        if(sse){
          // Normalize split CRLF safely only after complete events have arrived.
          let match;
          while((match=/\r?\n\r?\n/.exec(buffer))){
            const event=buffer.slice(0,match.index);buffer=buffer.slice(match.index+match[0].length);
            const data=event.split(/\r?\n/).filter(x=>x.startsWith('data:')).map(x=>x.slice(5).replace(/^ /,'')).join('\n');
            if(!data.trim())continue;
            const found=result(JSON.parse(data));if(found)return found.value;
          }
        }
        if(done){if(!sse){const found=result(JSON.parse(buffer));if(found)return found.value;}throw Error('mcp-missing-result');}
      }
    } finally {await reader.cancel().catch(()=>{});}
  }
  async initialize(){
    const info=await this.rpc('initialize',{protocolVersion:'2024-11-05',capabilities:{},clientInfo:{name:'serverless-hill-climb',version:'1'}});
    if(info.protocolVersion!=='2024-11-05')throw Error('unsupported-mcp-version');
    this.protocol=info.protocolVersion;
    await this.rpc('notifications/initialized',undefined,true);
  }
  async run(code){
    const result=await this.rpc('tools/call',{name:'run_js',arguments:this.lease.transport==='lambda'?{code,wait:true,execution_timeout_secs:15}:{code}});
    if(!Array.isArray(result?.content))throw Error('invalid-mcp-tool-result');
    return result;
  }
}

// Lambda is sessionless: no initialize/session reuse and no tool-call retries.
export class LambdaMcp extends NativeMcp {
  constructor(fetcher, secret, session, now=()=>Date.now()) {
    super(fetcher,{url:LAMBDA_ENDPOINT,token:'oauth-managed',sandbox:'lambda',transport:'lambda',session});
    if(typeof secret!=='string'||!secret)throw Error('lambda-oauth-not-configured');
    if(typeof session!=='string'||!/^pi-[a-f0-9]{64}$/.test(session))throw Error('invalid-lambda-session');
    this.protocol='2026-07-28';
    let cached,expires=0;
    this.getToken=async()=>{
      if(cached && now()<expires)return cached;
      const r=await fetcher(TOKEN_ENDPOINT,{method:'POST',redirect:'manual',headers:{'Content-Type':'application/x-www-form-urlencoded',Accept:'application/json'},body:new URLSearchParams({grant_type:'client_credentials',client_id:'pi-lambda-client',client_secret:secret}).toString(),signal:AbortSignal.timeout(15000)});
      if(!r.ok){await r.body?.cancel();throw Error('oauth-token-failed');}
      let data;
      try {
        const reader=r.body.getReader();let text='',bytes=0;const dec=new TextDecoder();
        try{for(;;){const {value,done}=await reader.read();if(done)break;bytes+=value.length;if(bytes>16384)throw Error();text+=dec.decode(value,{stream:true});}}finally{await reader.cancel().catch(()=>{});}
        data=JSON.parse(text);
      }catch{throw Error('oauth-invalid-response');}
      if(typeof data.access_token!=='string'||!data.access_token||data.token_type?.toLowerCase()!=='bearer'||!Number.isFinite(data.expires_in)||data.expires_in<=30)throw Error('oauth-invalid-response');
      cached=data.access_token;expires=now()+(Math.min(data.expires_in,300)-30)*1000;return cached;
    };
  }
  async initialize() {}
  async run(code) {
    const result=await super.run(code);
    const text=result.content.find(c=>c.type==='text')?.text;
    let execution;
    try {execution=JSON.parse(text);} catch {throw Error('invalid-inline-execution');}
    if(!['completed','failed','cancelled','timed_out'].includes(execution.status))throw Error('nonterminal-inline-execution');
    return {...result,isError:!!result.isError || execution.status!=='completed'};
  }
}
