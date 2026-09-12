// localStorage, not sessionStorage: sessionStorage is scoped to a single
// tab and is lost on a new tab/window (or a tab-discarding reload), which
// silently drops the token and makes every API call fail with "invalid
// API token" even though nothing is actually wrong server-side. Persist
// it the same way theme.ts persists the theme preference.
export const token=()=>localStorage.getItem('netra-token')||'';
export function setToken(v:string){if(v)localStorage.setItem('netra-token',v);else localStorage.removeItem('netra-token')}
function headers(extra:Record<string,string>={}){const h:{[k:string]:string}={...extra};if(token())h.Authorization=`Bearer ${token()}`;return h}
export async function api<T=unknown>(path:string, init:RequestInit={}):Promise<T>{const r=await fetch(path,{...init,headers:headers(init.headers as Record<string,string>||{})});if(!r.ok){if(r.status===401){setToken('');window.dispatchEvent(new Event('netra-auth-expired'))}throw new Error((await r.text())||r.statusText)}return r.json()}
export function streamURL(path:string){return path}
export function authHeaders(){return headers()}
