'use client';
import { useSyncExternalStore } from 'react';
import type { Locale } from './pokemon';
const subscribe=(fn:()=>void)=>{window.addEventListener('popstate',fn);window.addEventListener('pokehabitat:navigation',fn);return()=>{window.removeEventListener('popstate',fn);window.removeEventListener('pokehabitat:navigation',fn);};};
const view=()=>{const v=new URLSearchParams(window.location.search).get('view');return v&&['collection','arena','account','club'].includes(v)?v:'atlas';};
const habitat=()=>{const v=new URLSearchParams(window.location.search).get('habitat');return v&&['forest','water','mountain','grassland','cave','urban','unknown'].includes(v)?v:'all';};
export const useMainView=()=>useSyncExternalStore(subscribe,view,()=> 'atlas');
export const useHabitat=()=>useSyncExternalStore(subscribe,habitat,()=> 'all');
export const notifyNavigation=()=>window.dispatchEvent(new Event('pokehabitat:navigation'));
let memoryLocale:Locale='ru';
const language=():Locale=>{try{const saved=localStorage.getItem('pokehabitat-language');return saved==='ru'||saved==='en'?saved:memoryLocale;}catch{return memoryLocale;}};
const subscribeLanguage=(fn:()=>void)=>{window.addEventListener('storage',fn);window.addEventListener('pokehabitat:language',fn);return()=>{window.removeEventListener('storage',fn);window.removeEventListener('pokehabitat:language',fn);};};
export const useSiteLocale=()=>useSyncExternalStore(subscribeLanguage,language,()=> 'ru' as Locale);
export function setSiteLocale(value:Locale){memoryLocale=value;try{localStorage.setItem('pokehabitat-language',value);}catch{}window.dispatchEvent(new Event('pokehabitat:language'));}
export const useAtlasQuery=()=>useSyncExternalStore(subscribe,()=>window.location.search,()=> '');
