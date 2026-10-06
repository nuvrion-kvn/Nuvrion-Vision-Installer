'use client';
import {useRef,useState} from 'react';
import {Dialog,DialogContent,DialogTitle,DialogDescription,DialogClose} from './ui/dialog';
import {PokemonArt,TypeBadge,types} from './pokemon-visuals';
import {byId,type Locale} from '../lib/pokemon';
import type {Reward} from '../lib/game-client';
import type {CSSProperties} from 'react';
export function CardReveal({reward,locale,onClose}:{reward:Reward;locale:Locale;onClose:()=>void}){
 const [opened,setOpened]=useState(reward.kind==='evolution'),focus=useRef(typeof document==='undefined'?null:document.activeElement as HTMLElement|null);
 const p=byId.get(reward.pokemonId)!,tr=(ru:string,en:string)=>locale==='ru'?ru:en;
 return <Dialog open onOpenChange={v=>{if(!v)onClose();}}><DialogContent className='reveal-dialog' onCloseAutoFocus={e=>{e.preventDefault();focus.current?.focus();}}><DialogTitle>{reward.kind==='evolution'?tr('Новая ступень эволюции','A new evolution'):tr('Ваша находка','Your discovery')}</DialogTitle><DialogDescription>{opened?(reward.duplicate?tr('Карточка уже есть в коллекции. Получено 20 монет.','You already own this card. You received 20 coins.'):tr('Карточка добавлена в вашу коллекцию.','The card has been added to your collection.')):tr('Откройте покебол, чтобы увидеть карточку.','Open the Poké Ball to reveal your card.')}</DialogDescription><div className={`reveal-stage ${opened?'reveal-open':''}`} style={{'--pokemon-color':types[p.types[0]].color} as CSSProperties}>{opened?<><div className='reveal-rays' aria-hidden='true'/>{reward.fromId&&<PokemonArt id={reward.fromId} name='' className='evolution-before'/>}<PokemonArt id={p.id} name={p.name[locale]} className='reveal-art' priority/><h3>{p.name[locale]}</h3><div className='badge-row'>{p.types.map(t=><TypeBadge key={t} type={t} locale={locale}/>)}</div></>:<button className='pokeball-open' onClick={()=>setOpened(true)} aria-label={tr('Открыть покебол','Open Poké Ball')}><span/></button>}</div>{opened?<DialogClose asChild><button className='solid-button' onClick={onClose}>{tr('В коллекцию','Back to collection')}</button></DialogClose>:<button className='solid-button' onClick={()=>setOpened(true)}>{tr('Открыть','Open')}</button>}</DialogContent></Dialog>;
}
