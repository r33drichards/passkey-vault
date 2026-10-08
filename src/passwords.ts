export type PasswordEntry = { name:string; username:string; password:string; urls:string[]; notes:string };
function text(value:unknown, name:string, max:number):string {
  if(value===undefined || value===null)return '';
  if(typeof value!=='string' || value.length>max)throw new Error(`Invalid ${name} (maximum ${max} characters)`);
  return value;
}
export function parsePassword(value:unknown):PasswordEntry {
  if(!value || typeof value!=='object' || Array.isArray(value))throw new Error('Invalid login entry');
  const v=value as Record<string,unknown>, name=text(v.name,'name',200).trim();
  if(!name)throw new Error('Name this login');
  const urls=v.urls??[];
  if(!Array.isArray(urls)||urls.length>20)throw new Error('Maximum 20 URLs per login');
  return {name,username:text(v.username,'username',1000),password:text(v.password,'password',4000),notes:text(v.notes,'notes',8000),urls:urls.map(u=>text(u,'URL',8192))};
}
export function parseBitwarden(value:unknown):{entries:PasswordEntry[]; skipped:number; omitted:number} {
  if(!value || typeof value!=='object' || Array.isArray(value))throw new Error('Choose an unencrypted Bitwarden JSON export');
  const v=value as Record<string,unknown>;
  if(v.encrypted===true)throw new Error('Encrypted Bitwarden exports are not supported. Export as unencrypted JSON.');
  if(!Array.isArray(v.items)||v.items.length>2000)throw new Error('Expected Bitwarden items (maximum 2000)');
  const entries:PasswordEntry[]=[];let skipped=0,omitted=0;
  for(const item of v.items){
    if(!item || typeof item!=='object')throw new Error('Invalid Bitwarden item');
    if(item.type!==1){skipped++;continue;}
    if(!item.login || typeof item.login!=='object')throw new Error('Invalid Bitwarden login');
    const uris=item.login.uris??[];if(!Array.isArray(uris))throw new Error('Invalid Bitwarden URLs');
    entries.push(parsePassword({name:item.name,username:item.login.username,password:item.login.password,notes:item.notes,urls:uris.map((u: any)=>u?.uri)}));
    if(uris.some((u:any)=>u?.match!=null) || item.login.totp || item.login.fido2Credentials?.length || item.fields?.length || item.attachments?.length || item.passwordHistory?.length || item.folderId || item.collectionIds?.length)omitted++;
  }
  if(entries.length>500)throw new Error('Maximum 500 logins per import');
  return {entries,skipped,omitted};
}
