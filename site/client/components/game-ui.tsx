'use client';
import { useId, type FormEvent, type ReactNode } from 'react';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { LoaderCircle } from 'lucide-react';
export function Feedback({error,message,children}:{error?:string|null;message?:string|null;children?:ReactNode}){return error||message?<div className={`game-feedback ${error?'feedback-error':''}`} role={error?'alert':'status'}>{error||message}{children}</div>:null;}
export function GameField({label,hint,error,type='text',value,onChange,autoComplete,maxLength=128,children}:{label:string;hint?:string;error?:string;type?:string;value?:string;onChange?:(v:string)=>void;autoComplete?:string;maxLength?:number;children?:ReactNode}){
 const id=useId();return <div className='game-field'><Label htmlFor={id}>{label}</Label>{children||<Input id={id} type={type} value={value} onChange={e=>onChange?.(e.target.value)} autoComplete={autoComplete} maxLength={maxLength} aria-invalid={!!error} aria-describedby={hint||error?`${id}-hint`:undefined}/>}<span id={`${id}-hint`} className={error?'field-error':'field-hint'}>{error||hint}</span></div>;
}
export function GameForm({onSubmit,children,busy}:{onSubmit:()=>Promise<void>;children:ReactNode;busy:boolean}){
 const submit=async(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();const form=e.currentTarget;if(busy)return;await onSubmit();requestAnimationFrame(()=>form.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());};
 return <form noValidate onSubmit={submit} aria-busy={busy}>{children}</form>;
}
export function PendingButton({busy,children,onClick,disabled=false,className='solid-button',type='button'}:{busy:boolean;children:ReactNode;onClick?:()=>void;disabled?:boolean;className?:string;type?:'button'|'submit'}){return <button type={type} className={className} disabled={busy||disabled} onClick={onClick}>{busy&&<LoaderCircle size={16} className='spinner' aria-hidden='true'/>}{children}</button>;}
