'use client';
import { useCallback,useEffect,useRef,useState } from 'react';
import type { Battle, Order } from '../server/battle';
export type Profile={id:string;username:string;credits:number;team:number[];expeditionAt:number;wins:number;losses:number;version:number;createdAt:number;cards:{id:number;source:string;createdAt:number}[];trainer:{avatar:number;cover:string;favorites:number[];xp:number;level:number;pveWins:number;evolutions:number}};
export type GameRoom=Omit<Battle,'orders'>&{code:string;status:string;version:number;you:number;ownOrder:Order|null;opponentReady:boolean};
export type Reward={fromId?:number;pokemonId:number;duplicate:boolean;coins:number;kind:string};
export type GameResult={profile?:Profile|null;room?:GameRoom;recoveryCode?:string;reward?:Reward};
export class ApiError extends Error{constructor(public code:string,public field?:string){super(code);}}
export async function gameFetch<T>(path:string,body?:unknown,signal?:AbortSignal):Promise<T>{
 try{const r=await fetch(`/api/game/${path}`,{method:body===undefined?'GET':'POST',credentials:'same-origin',cache:'no-store',headers:body===undefined?{}:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),signal});const data=await r.json() as T & {error?:string;field?:string};if(!r.ok)throw new ApiError(data.error||'unavailable',data.field);return data;}
 catch(e){if(e instanceof ApiError||(e instanceof DOMException&&e.name==='AbortError'))throw e;throw new ApiError('network');}
}
export function useGame(){
 const [profile,setProfile]=useState<Profile|null>(null),[loading,setLoading]=useState(true),[busy,setBusy]=useState(false),[error,setError]=useState<ApiError|null>(null);
 const mounted=useRef(true),lock=useRef(false),epoch=useRef(0);
 const accept=useCallback((next:Profile|null)=>setProfile(old=>old&&next&&old.id===next.id&&old.version>next.version?old:next),[]);
 const refresh=useCallback(async(signal?:AbortSignal)=>{const n=++epoch.current;await Promise.resolve();try{const r=await gameFetch<{profile:Profile|null}>('me',undefined,signal);if(mounted.current&&n===epoch.current){accept(r.profile);setError(null);}}catch(e){if(mounted.current&&n===epoch.current&&!(e instanceof DOMException&&e.name==='AbortError'))setError(e as ApiError);}finally{if(mounted.current&&n===epoch.current)setLoading(false);}},[accept]);
 useEffect(()=>{mounted.current=true;const controller=new AbortController();const initial=setTimeout(()=>void refresh(controller.signal),0);return()=>{clearTimeout(initial);mounted.current=false;controller.abort();};},[refresh]);
 const request=useCallback(async(path:string,body:unknown)=>{if(lock.current)throw new ApiError('busy');lock.current=true;setBusy(true);setError(null);++epoch.current;try{const r=await gameFetch<GameResult>(path,body);if(mounted.current&&Object.hasOwn(r,'profile'))accept(r.profile??null);return r;}catch(e){if(mounted.current){setError(e as ApiError);if((e as ApiError).code==='unauthorized')accept(null);}throw e;}finally{lock.current=false;if(mounted.current)setBusy(false);}},[accept]);
 return {profile,loading,busy,error,request,refresh,accept,clearError:()=>setError(null)};
}
