export const token=()=>sessionStorage.getItem('netra-token')||'';
export function setToken(v:string){if(v)sessionStorage.setItem('netra-token',v);else sessionStorage.removeItem('netra-token')}
function headers(extra:Record<string,string>={}){const h:{[k:string]:string}={...extra};if(token())h.Authorization=`Bearer ${token()}`;return h}
export async function api<T=unknown>(path:string, init:RequestInit={}):Promise<T>{const r=await fetch(path,{...init,headers:headers(init.headers as Record<string,string>||{})});if(!r.ok)throw new Error((await r.text())||r.statusText);return r.json()}
export function streamURL(path:string){return path}
export function authHeaders(){return headers()}
