"""Run in authorized CI with CF_TOKEN and CF_ACCOUNT. Never prints secrets."""
import base64
import json
import os
from pathlib import Path
import secrets
import time
import urllib.error
import urllib.request

NAME = 'serverless-hill-climb'
OWNER = '57335981'
ACCOUNT = os.environ['CF_ACCOUNT']
TOKEN = os.environ['CF_TOKEN']
BASE = f'https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/workers'

def api(path, method='GET', data=None, content_type='application/json'):
    if isinstance(data, dict):
        data = json.dumps(data).encode()
    request = urllib.request.Request(BASE + path, method=method, data=data,
        headers={'Authorization': 'Bearer '+TOKEN, 'Content-Type':content_type})
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            result = json.load(response)
    except urllib.error.HTTPError as error:
        # Never log response bodies: upload errors can include bindings.
        raise RuntimeError(f'Cloudflare API {method} {path} returned HTTP {error.code}') from None
    if not result.get('success'):
        raise RuntimeError('Cloudflare API rejected operation')
    return result['result']

def multipart(metadata, script):
    boundary = '----durablepi'+secrets.token_hex(12)
    chunks=[]
    for name, filename, mime, body in [
        ('metadata','metadata.json','application/json',json.dumps(metadata).encode()),
        ('worker.mjs','worker.mjs','application/javascript+module',script),
    ]:
        chunks.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\nContent-Type: {mime}\r\n\r\n'.encode()+body+b'\r\n')
    chunks.append(f'--{boundary}--\r\n'.encode())
    return b''.join(chunks),f'multipart/form-data; boundary={boundary}'

scripts=api('/scripts')
exists=any(s.get('id')==NAME for s in scripts)
subdomain=api('/subdomain')['subdomain']
if subdomain != 'rwendt1337':
    raise RuntimeError('Unexpected account workers.dev subdomain')
origin=f'https://{NAME}.{subdomain}.workers.dev'
bindings=[
    {'type':'plain_text','name':'PUBLIC_ORIGIN','text':origin},
    {'type':'plain_text','name':'GITHUB_OWNER_ID','text':OWNER},
    {'type':'plain_text','name':'GITHUB_OWNER_LOGIN','text':'r33drichards'},
    {'type':'durable_object_namespace','name':'AUTH','class_name':'OwnerAuthority'},
]
metadata={'compatibility_flags':['nodejs_compat'],'main_module':'worker.mjs','compatibility_date':'2026-10-27','bindings':bindings,'observability':{'enabled':False}}
if exists:
    settings=api(f'/scripts/{NAME}/settings')
    prior={b['name']:b for b in settings.get('bindings',[])}
    if prior.get('GITHUB_OWNER_ID',{}).get('text')!=OWNER or prior.get('AUTH',{}).get('class_name')!='OwnerAuthority' or prior.get('VAULT_KEY',{}).get('type')!='secret_text':
        raise RuntimeError('Existing Worker does not match this application; refusing overwrite')
    metadata['keep_bindings']=['secret_text']
else:
    bindings.append({'type':'secret_text','name':'VAULT_KEY','text':base64.b64encode(secrets.token_bytes(32)).decode()})
    metadata['migrations']={'new_tag':'auth-v1','new_sqlite_classes':['OwnerAuthority']}

artifact=Path(__file__).parent/'dist/worker.mjs'
body,ctype=multipart(metadata,artifact.read_bytes())
api(f'/scripts/{NAME}','PUT',body,ctype)
api(f'/scripts/{NAME}/subdomain','POST',{'enabled':True,'previews_enabled':False})

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None
client=urllib.request.build_opener(NoRedirect)
def get(path,method='GET'):
    request=urllib.request.Request(origin+path,method=method,headers={'User-Agent':'durable-pi-modal-smoke/1.0'})
    try:
        with client.open(request,timeout=20) as response:
            return response.status,response.read().decode(),dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code,error.read().decode(),dict(error.headers)

for attempt in range(8):
    status,body,_=get('/health')
    if status==200 and json.loads(body).get('service')==NAME: break
    time.sleep(5)
else: raise RuntimeError('Deployed health check failed')
status,body,headers=get('/admin')
if status!=200 or ('Set up with GitHub' not in body and 'Continue with GitHub' not in body):
    raise RuntimeError('Admin page is not serving')
for path,method,expected in [('/admin/chatgpt','GET',401),('/admin/chatgpt/start','POST',401),('/internal/credential','GET',404),('/webhook','POST',401),('/github/events','POST',503),('/setup/callback?state=wrong&code=invalidtestcode','GET',400)]:
    actual,_,_=get(path,method)
    if path=='/github/events' and actual==401: continue # Configured app rejects unsigned calls.
    # Once setup is complete, setup/callback is permanently disabled.
    if path.startswith('/setup') and actual==409: continue
    if actual!=expected: raise RuntimeError(f'Access check failed: {path} {actual}')
summary=f'Hill Climb admin deployed: {origin}/admin\nOwner ID: {OWNER}\nUnauthenticated ChatGPT routes rejected; credential export absent.\nGitHub App creation and repository installation remain to be completed by owner.\n'
print(summary)
if os.environ.get('GITHUB_STEP_SUMMARY'):
    with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as f: f.write(summary)

