'use client';
import { useEffect, useRef } from 'react';
import type { Move } from '../lib/pokemon';
const colors:Record<string,string>={fire:'#df6b28',water:'#329bc8',grass:'#478641',electric:'#d5a71a',ice:'#4baabe',psychic:'#ae5aa6',ghost:'#7560a9',dark:'#635373',rock:'#967245',ground:'#ac8855',poison:'#9c66af',fighting:'#bf694b',dragon:'#667dc8',steel:'#758e9c',bug:'#829443',flying:'#6e9da9',fairy:'#d47f9f',normal:'#688275'};
export function effectFamily(move:Move){
 const s=move.slug||move.name.en.toLowerCase().replaceAll(' ','-');
 if(s==='transform')return 'transform';
 if(/absorb|drain/.test(s))return 'drain';
 if(s==='confusion')return 'confusion';
 if(/whip|tentacle/.test(s))return 'vine';
 if(/leaf|petal|seed/.test(s))return 'leaves';
 if(/bubble/.test(s))return 'bubbles';
 if(/surf|wave|waterfall/.test(s))return 'wave';
 if(/flame-wheel|fire-spin/.test(s))return 'flame-ring';
 if(/ember/.test(s))return 'embers';
 if(/flame|fire-blast|burn/.test(s))return 'flame';
 if(/thunder|shock|spark|zap|electro/.test(s))return 'lightning';
 if(/beam|gun|pump|cannon/.test(s))return move.type==='ice'?'ice-beam':'beam';
 if(/rock|stone|meteor|egg-bomb/.test(s))return 'boulders';
 if(/earth|dig|magnitude|mud/.test(s))return 'ground';
 if(/scratch|slash|claw|cut|fury/.test(s))return 'slash';
 if(/bite|fang|crunch/.test(s))return 'bite';
 if(/punch|kick|chop|slam|tackle|headbutt|peck|horn|struggle|quick-attack/.test(s))return 'impact';
 if(/gust|wind|twister|air/.test(s))return 'wind';
 if(/voice|sing|echo|sonic|screech|sound/.test(s))return 'sound';
 if(/aura|sphere|ball|pulse/.test(s))return 'orb';
 return ({fire:'flame',water:'beam',grass:'leaves',electric:'lightning',ice:'ice-beam',psychic:'psychic',ghost:'orb',poison:'toxic',fighting:'impact',ground:'ground',rock:'boulders',flying:'wind',bug:'leaves',steel:'slash',dragon:'orb',fairy:'psychic',dark:'slash',normal:'impact'} as Record<string,string>)[move.type]||'impact';
}
export function MoveEffect({move,onComplete,direction='right',arena=false}:{move:Move|null;onComplete:()=>void;direction?:'left'|'right';arena?:boolean}){
 const ref=useRef<HTMLCanvasElement>(null),done=useRef(onComplete);useEffect(()=>{done.current=onComplete;},[onComplete]);
 useEffect(()=>{
  if(!move||!ref.current)return;
  const el=ref.current,ctx=el.getContext('2d');if(!ctx){done.current();return;}
  const w=el.clientWidth,h=el.clientHeight,dpr=Math.min(window.devicePixelRatio||1,2);
  el.width=w*dpr;el.height=h*dpr;ctx.scale(dpr,dpr);
  const reduced=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const family=effectFamily(move),color=colors[move.type]||colors.normal,duration=reduced?650:1550;
  let frame=0;const start=performance.now();
  const sx=w*(arena?.23:.5),tx=w*(arena?.77:.92),cy=h*.48;
  const line=(points:number[][],width:number,alpha=1)=>{ctx.globalAlpha=alpha;ctx.lineWidth=width;ctx.strokeStyle=color;ctx.lineCap='round';ctx.lineJoin='round';ctx.beginPath();points.forEach(([x,y],i)=>i?ctx.lineTo(x,y):ctx.moveTo(x,y));ctx.stroke();};
  const dot=(x:number,y:number,r:number,alpha=1)=>{ctx.globalAlpha=alpha;ctx.fillStyle=color;ctx.beginPath();ctx.arc(x,y,Math.max(.1,r),0,Math.PI*2);ctx.fill();};
  function render(now:number){
   if(!ctx||!move)return;const t=Math.min(1,(now-start)/duration),p=reduced?.65:t,a=reduced?.4:Math.sin(t*Math.PI)*.8,x=sx+(tx-sx)*Math.min(1,p*1.4);
   ctx.clearRect(0,0,w,h);ctx.save();if(direction==='left'){ctx.translate(w,0);ctx.scale(-1,1);}
   ctx.shadowColor=color;ctx.shadowBlur=reduced?0:10;
   if(family==='lightning'){
    for(let branch=0;branch<3;branch++){const pts=Array.from({length:9},(_,i)=>[sx+(x-sx)*i/8,cy+Math.sin(i*3+branch+(reduced?0:Math.floor(p*12)))*((i===0||i===8)?0:15+branch*5)]);line(pts,branch?1.7:4,a*(1-branch*.25));}dot(x,cy,9,a);
   }else if(['beam','ice-beam','flame'].includes(family)){
    const width=family==='flame'?19:family==='beam'?11:6;
    line([[sx,cy],[x,cy]],width,a*.65);line([[sx,cy],[x,cy]],3,a);
    for(let i=0;i<30;i++){const q=(p*2+i/30)%1,xx=sx+(x-sx)*q,yy=cy+Math.sin(i*2.4+q*10)*(family==='flame'?q*25:8);if(family==='ice-beam'){ctx.globalAlpha=a;ctx.fillStyle=color;ctx.beginPath();ctx.moveTo(xx,yy-9);ctx.lineTo(xx+4,yy);ctx.lineTo(xx,yy+9);ctx.lineTo(xx-4,yy);ctx.fill();}else dot(xx,yy,2+(i%4),a*(.4+q*.6));}
   }else if(family==='vine'){
    for(let j=0;j<2;j++)line(Array.from({length:32},(_,i)=>[sx+(x-sx)*i/31,cy+Math.sin(i/31*Math.PI*2-p*8+j*Math.PI)*25*Math.sin(i/31*Math.PI)]),4,a);dot(x,cy,5,a);
   }else if(family==='bubbles'||family==='toxic'){
    for(let i=0;i<22;i++){const q=(p*1.6+i*.037)%1,xx=sx+(tx-sx)*q,yy=cy+Math.sin(i*2.3)*q*65-q*18;ctx.globalAlpha=a*(1-q*.4);ctx.strokeStyle=color;ctx.lineWidth=2;ctx.beginPath();ctx.arc(xx,yy,4+i%8,0,Math.PI*2);if(family==='toxic')ctx.fill();else ctx.stroke();}
   }else if(family==='wave'){
    for(let j=0;j<5;j++)line(Array.from({length:35},(_,i)=>[sx+(tx-sx)*i/34,cy+Math.sin(i/34*7-p*8+j*.4)*30+12*j]),4,a*(1-j*.13));
   }else if(family==='leaves'){
    ctx.fillStyle=color;for(let i=0;i<20;i++){const q=Math.min(1,Math.max(0,(p-i*.019)*1.6)),xx=sx+(tx-sx)*q,yy=cy+Math.sin(i*2.4)*55*Math.sin(q*Math.PI);ctx.globalAlpha=a;ctx.beginPath();ctx.ellipse(xx,yy,11,3.5,i*.7+q*3,0,Math.PI*2);ctx.fill();}
   }else if(family==='boulders'){
    for(let i=0;i<5;i++){const q=Math.min(1,Math.max(0,(p-i*.06)*1.7)),xx=sx+(tx-sx)*q,yy=cy-85*Math.sin(q*Math.PI)+(i-2)*15;ctx.globalAlpha=a;ctx.fillStyle=color;ctx.beginPath();for(let j=0;j<6;j++){const ang=j*Math.PI/3+p*2;const px=xx+Math.cos(ang)*(11+i*2),py=yy+Math.sin(ang)*(11+i*2);if(j)ctx.lineTo(px,py);else ctx.moveTo(px,py);}ctx.closePath();ctx.fill();}
   }else if(family==='slash'){
    for(let j=0;j<3;j++){const q=Math.min(1,Math.max(0,(p-j*.1)*2));line([[tx-42+q*20,cy-45+j*14],[tx-35+q*48,cy-9+j*14],[tx-30+q*65,cy+36+j*14]],3.5,a);}
   }else if(family==='bite'){
    for(const sign of [-1,1]){const gap=(1-Math.sin(p*Math.PI))*35+9;line(Array.from({length:9},(_,i)=>[tx-45+i*10,cy+sign*(gap+(i%2?10:0))]),3.5,a);}
   }else if(family==='ground'){
    for(let j=0;j<3;j++)line(Array.from({length:12},(_,i)=>[sx+(x-sx)*i/11,cy+30+j*13+Math.sin(i*4)*10]),3,a);
    for(let i=0;i<15;i++)dot(x+(i%5-2)*10,cy+35-Math.abs(Math.sin(p*6+i))*50,3+i%3,a);
   }else if(family==='wind'||family==='flame-ring'||family==='sound'){
    for(let i=0;i<5;i++){const q=(p+i*.11)%1,xx=family==='flame-ring'?sx+(tx-sx)*p:sx+(tx-sx)*q;ctx.globalAlpha=a*(1-q*.4);ctx.strokeStyle=color;ctx.lineWidth=family==='sound'?2:3;ctx.beginPath();ctx.ellipse(xx,cy,8+q*22,16+q*50,0,family==='wind'?p*6:0,family==='wind'?p*6+Math.PI*1.7:Math.PI*2);ctx.stroke();}
   }else if(family==='psychic'||family==='transform'){
    for(let i=0;i<3;i++){ctx.globalAlpha=a;ctx.strokeStyle=color;ctx.lineWidth=2;ctx.beginPath();ctx.ellipse(family==='transform'?sx:x,cy,25+i*19,35+i*17,p*(i%2?1:-1)*2,0,Math.PI*2);ctx.stroke();}for(let i=0;i<12;i++)dot(x+Math.cos(i*2.4+p*3)*55,cy+Math.sin(i*2.4+p*3)*65,3,a);
   }else if(family==='embers'){
    for(let i=0;i<28;i++){const q=Math.min(1,Math.max(0,(p-i*.018)*1.6));dot(sx+(tx-sx)*q,cy+Math.sin(i*2.1)*q*35-q*22,2+i%3,a);}
   }else if(family==='drain'){
    for(let i=0;i<20;i++){const q=(p*1.3+i/20)%1;dot(tx-(tx-sx)*q,cy+Math.sin(i*2.4)*20*Math.sin(q*Math.PI),3+i%3,a);}
   }else if(family==='confusion'){
    line(Array.from({length:80},(_,i)=>{const q=i/79,angle=q*Math.PI*7+p*5;return [x+Math.cos(angle)*(10+q*35),cy+Math.sin(angle)*(15+q*50)];}),2.5,a);
   }else if(family==='orb'){
    dot(x,cy,12+Math.sin(p*Math.PI)*10,a);ctx.globalAlpha=a*.45;ctx.strokeStyle=color;ctx.lineWidth=2;ctx.beginPath();ctx.arc(x,cy,26,0,Math.PI*2);ctx.stroke();line([[Math.max(sx,x-70),cy],[x,cy]],4,a*.4);
   }else{
    const q=Math.min(1,p*1.5),size=15+Math.sin(p*Math.PI)*25;line([[sx,cy],[sx+(tx-sx)*q,cy]],7,a*.4);
    for(let i=0;i<8;i++){const ang=i*Math.PI/4;line([[tx+Math.cos(ang)*size*.4,cy+Math.sin(ang)*size*.4],[tx+Math.cos(ang)*size,cy+Math.sin(ang)*size]],3,a);}
   }
   ctx.restore();ctx.globalAlpha=1;if(t<1)frame=requestAnimationFrame(render);else{ctx.clearRect(0,0,w,h);done.current();}
  }
  frame=requestAnimationFrame(render);return()=>{cancelAnimationFrame(frame);ctx.clearRect(0,0,w,h);};
 },[move,direction,arena]);
 return <canvas ref={ref} className={`move-canvas ${arena?'arena-effect':''}`} aria-hidden='true'/>;
}
