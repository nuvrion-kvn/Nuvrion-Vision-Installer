import bcrypt from 'bcryptjs';
import { GameError } from './game-errors';
import { trainerDetails, extraGame, practiceOrder } from './trainer-service';
import { gameDb, gameConfig } from '../db/game';
import { pokemon, byId } from '../lib/pokemon';
import { makeSide, choose, random, validOrder, resolveRound, type Battle, type Order } from './battle';

export type Player = { id:string; username:string; password_hash:string; recovery_hash:string; credits:number; team:string; expedition_at:number; wins:number; losses:number; version:number; created_at:number };
type Room = { code:string; host_id:string; guest_id:string|null; status:string; state:string; version:number; updated_at:number };
const DAY=86400000, COOKIE='__Host-pokehabitat';
const json=(data:unknown,status=200,cookie?:string)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...(cookie?{'Set-Cookie':cookie}:{})}});
function token(){const bytes=crypto.getRandomValues(new Uint8Array(32));return btoa(String.fromCharCode(...bytes)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
async function digest(value:string){const bytes=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value));return Array.from(new Uint8Array(bytes),v=>v.toString(16).padStart(2,'0')).join('');}
async function keyed(value:string){const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(gameConfig().pepper),{name:'HMAC',hash:'SHA-256'},false,['sign']);return btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(value)))));}
function cookie(value:string,age=7*86400){return `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`;}
const cookieToken=(r:Request)=>r.headers.get('Cookie')?.split(';').map(x=>x.trim()).find(x=>x.startsWith(`${COOKIE}=`))?.slice(COOKIE.length+1)||'';
function credentials(body:Record<string,unknown>,creating=false){
  const username=typeof body.username==='string'?body.username.trim().toLowerCase():'';
  if(!/^[a-z0-9_]{3,20}$/.test(username))throw new GameError('username',400,'username');
  const password=typeof body.password==='string'?body.password:'';
  if(password.length<(creating?10:1)||password.length>128)throw new GameError('password',400,'password');
  return {username,password};
}
async function rate(req:Request,scope:string,account:string,limit:number,period=900000){
  const db=gameDb(), now=Date.now(), window=Math.floor(now/period)*period;
  const key=await keyed(`rate:${scope}:${account}`);
  const row=await db.prepare('INSERT INTO rate_limits (key,window_at,count) VALUES (?,?,1) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN window_at=? THEN count+1 ELSE 1 END, window_at=? RETURNING count').bind(key,window,window,window).first<{count:number}>();
  if(!row||row.count>limit)throw new GameError('rate',429);
  if(random()<.01)await db.batch([db.prepare('DELETE FROM rate_limits WHERE window_at<?').bind(now-DAY*2),db.prepare('DELETE FROM sessions WHERE expires_at<?').bind(now)]);
}
async function session(req:Request){
  const t=cookieToken(req);if(!/^[A-Za-z0-9_-]{43}$/.test(t))return null;
  return gameDb().prepare('SELECT p.* FROM sessions s JOIN players p ON p.id=s.player_id WHERE s.token_hash=? AND s.expires_at>?').bind(await digest(t),Date.now()).first<Player>();
}
async function requirePlayer(req:Request){const p=await session(req);if(!p)throw new GameError('unauthorized',401);return p;}
async function newSession(id:string){const t=token();await gameDb().prepare('INSERT INTO sessions (token_hash,player_id,expires_at) VALUES (?,?,?)').bind(await digest(t),id,Date.now()+DAY*7).run();return t;}
async function profile(id:string){
  const db=gameDb(),p=await db.prepare('SELECT id,username,credits,team,expedition_at,wins,losses,created_at,version FROM players WHERE id=?').bind(id).first<Player>();
  if(!p)throw new GameError('unauthorized',401);
  const cards=await db.prepare('SELECT pokemon_id AS id,source,created_at AS createdAt FROM cards WHERE player_id=? ORDER BY created_at,pokemon_id').bind(id).all();
  return {id:p.id,username:p.username,credits:p.credits,team:JSON.parse(p.team) as number[],expeditionAt:p.expedition_at,wins:p.wins,losses:p.losses,createdAt:p.created_at,version:p.version,cards:cards.results,...await trainerDetails(p,cards.results as {id:number}[])};
}
async function validateTeam(p:Player,ids:unknown){
  if(!Array.isArray(ids)||ids.length!==3||new Set(ids).size!==3||ids.some(x=>!Number.isInteger(x)||!byId.has(x)))throw new GameError('team');
  if(ids.reduce((sum,id)=>sum+byId.get(id)!.stats.reduce((a,b)=>a+b,0),0)>1500)throw new GameError('teamPower');
  const owned=await gameDb().prepare('SELECT pokemon_id FROM cards WHERE player_id=?').bind(p.id).all<{pokemon_id:number}>();
  if(ids.some(id=>!owned.results.some(c=>c.pokemon_id===id)))throw new GameError('ownership',403);
  return ids as number[];
}
const evolved=(id:number)=>byId.get(id)!.evolution.edges.some(e=>e.to===id);
const legendary=(id:number)=>{const p=byId.get(id)!;return !!(p.isLegendary||p.isMythical||[144,145,146,150,151].includes(id));};
const common=()=>pokemon.filter(p=>!legendary(p.id)&&!evolved(p.id)&&p.stats.reduce((a,b)=>a+b,0)<=450);
async function acquisition(p:Player,body:Record<string,unknown>,kind:'expedition'|'pack'){
  if(typeof body.key!=='string'||!/^[a-f0-9-]{36}$/i.test(body.key))throw new GameError('request');
  const db=gameDb(),id=`${p.id}:${body.key}`;
  const previous=await db.prepare('SELECT result,kind FROM claims WHERE id=? AND player_id=?').bind(id,p.id).first<{result:string;kind:string}>();
  if(previous){if(previous.kind!==kind)throw new GameError('request');return JSON.parse(previous.result);}
  const now=Date.now();
  if(kind==='expedition'&&p.expedition_at>now-DAY)throw new GameError('cooldown',409);
  if(kind==='pack'&&p.credits<100)throw new GameError('coins',409);
  let pool=common();
  if(kind==='expedition'){
    if(!['forest','water','mountain','grassland','cave','urban','unknown'].includes(String(body.habitat)))throw new GameError('habitat');
    pool=pokemon.filter(x=>x.habitat===body.habitat&&!legendary(x.id));
  }else{
    const roll=random();pool=roll<.01?pokemon.filter(x=>legendary(x.id)):roll<.10?pokemon.filter(x=>evolved(x.id)&&!legendary(x.id)):common();
  }
  if(!pool.length)throw new GameError('habitat');
  const card=choose(pool),exists=!!await db.prepare('SELECT pokemon_id FROM cards WHERE player_id=? AND pokemon_id=?').bind(p.id,card.id).first();
  const reward={pokemonId:card.id,duplicate:exists,coins:exists?20:0,kind};
  const nonce=crypto.randomUUID();
  const update=kind==='pack'?'UPDATE players SET credits=credits-100+?,version=version+1,last_operation=? WHERE id=? AND version=? AND credits>=100 AND NOT EXISTS(SELECT 1 FROM claims WHERE id=?)':'UPDATE players SET credits=credits+?,expedition_at=?,version=version+1,last_operation=? WHERE id=? AND version=? AND expedition_at<=? AND NOT EXISTS(SELECT 1 FROM claims WHERE id=?)';
  const args=kind==='pack'?[reward.coins,nonce,p.id,p.version,id]:[reward.coins,now,nonce,p.id,p.version,now-DAY,id];
  const result=await db.batch([
    db.prepare(update).bind(...args),
    db.prepare('INSERT INTO claims (id,player_id,kind,result,created_at) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM players WHERE id=? AND last_operation=?)').bind(id,p.id,kind,JSON.stringify(reward),now,p.id,nonce),
    db.prepare('INSERT OR IGNORE INTO cards (player_id,pokemon_id,source,created_at) SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM players WHERE id=? AND last_operation=?)').bind(p.id,card.id,kind,now,p.id,nonce)
  ]);
  if(!result[0].meta.changes){const retry=await db.prepare('SELECT result FROM claims WHERE id=? AND player_id=?').bind(id,p.id).first<{result:string}>();if(retry)return JSON.parse(retry.result);throw new GameError('conflict',409);}
  return reward;
}
function visible(room:Room,p:Player){
  const state=JSON.parse(room.state) as Battle,you=state.sides.findIndex(s=>s.id===p.id);
  if(you<0)throw new GameError('ownership',403);
  const {orders,...safe}=state;
  return {code:room.code,status:room.status,version:room.version,...safe,you,ownOrder:orders[you]||null,opponentReady:!!orders[1-you]};
}
async function readRoom(code:unknown){
  if(typeof code!=='string'||!/^[A-Z2-9]{6}$/.test(code))throw new GameError('room',404);
  const r=await gameDb().prepare('SELECT * FROM rooms WHERE code=?').bind(code).first<Room>();
  if(!r)throw new GameError('room',404);return r;
}
async function commitRoom(room:Room,state:Battle,status:string){
  const db=gameDb(),now=Date.now(),version=room.version+1;
  const statements=[db.prepare('UPDATE rooms SET state=?,status=?,version=version+1,updated_at=? WHERE code=? AND version=?').bind(JSON.stringify(state),status,now,room.code,room.version)];
  if(status==='finished'&&!state.practice){
    for(const side of state.sides){
      statements.push(db.prepare(`INSERT OR IGNORE INTO battle_rewards (player_id,room_code,day,credits,won,applied)
        SELECT ?,code,?,CASE WHEN json_extract(state,'$.reason')='draw' THEN 0 WHEN json_extract(state,'$.reason')='forfeit' AND json_extract(state,'$.round')<3 THEN 0
        WHEN (SELECT COUNT(*) FROM battle_rewards WHERE player_id=? AND day=? AND credits>0)>=3 THEN 0
        WHEN json_extract(state,'$.winner')=? THEN 30 ELSE 10 END,
        CASE WHEN json_extract(state,'$.reason')='draw' THEN -1 WHEN json_extract(state,'$.winner')=? THEN 1 ELSE 0 END,0
        FROM rooms WHERE code=? AND version=? AND status='finished'`).bind(side.id,Math.floor(now/DAY),side.id,Math.floor(now/DAY),side.id,side.id,room.code,version));
      statements.push(db.prepare(`UPDATE players SET credits=credits+COALESCE((SELECT credits FROM battle_rewards WHERE player_id=? AND room_code=? AND applied=0),0),
        wins=wins+CASE WHEN (SELECT won FROM battle_rewards WHERE player_id=? AND room_code=? AND applied=0)=1 THEN 1 ELSE 0 END,
        losses=losses+CASE WHEN (SELECT won FROM battle_rewards WHERE player_id=? AND room_code=? AND applied=0)=0 THEN 1 ELSE 0 END,
        version=version+1 WHERE id=? AND EXISTS(SELECT 1 FROM battle_rewards WHERE player_id=? AND room_code=? AND applied=0)`).bind(side.id,room.code,side.id,room.code,side.id,room.code,side.id,side.id,room.code));
      statements.push(db.prepare('UPDATE battle_rewards SET applied=1 WHERE player_id=? AND room_code=? AND applied=0').bind(side.id,room.code));
    }
  }
  if(status==='finished'&&state.practice){
    const id=state.sides[0].id, won=state.winner===id?1:0;
    statements.push(db.prepare('INSERT OR IGNORE INTO trainer_profiles (player_id) VALUES (?)').bind(id));
    statements.push(db.prepare(`INSERT OR IGNORE INTO practice_results (player_id,room_code,day,won,applied) SELECT ?,code,?,?,0 FROM rooms WHERE code=? AND version=? AND status='finished'`).bind(id,Math.floor(now/DAY),won,room.code,version));
    statements.push(db.prepare('UPDATE trainer_profiles SET xp=xp+?,pve_wins=pve_wins+? WHERE player_id=? AND EXISTS(SELECT 1 FROM practice_results WHERE player_id=? AND room_code=? AND applied=0)').bind(won?15:5,won,id,id,room.code));
    statements.push(db.prepare('UPDATE players SET version=version+1 WHERE id=? AND EXISTS(SELECT 1 FROM practice_results WHERE player_id=? AND room_code=? AND applied=0)').bind(id,id,room.code));
    statements.push(db.prepare('UPDATE practice_results SET applied=1 WHERE player_id=? AND room_code=?').bind(id,room.code));
  }
  if(status==='finished'||status==='cancelled')statements.push(db.prepare("DELETE FROM player_locks WHERE room_code=? AND EXISTS(SELECT 1 FROM rooms WHERE code=? AND status IN ('finished','cancelled'))").bind(room.code,room.code));
  const result=await db.batch(statements);
  if(!result[0].meta.changes)throw new GameError('conflict',409);
  return {...room,state:JSON.stringify(state),status,version,updated_at:now};
}
async function advance(room:Room){
  const state=JSON.parse(room.state) as Battle;
  if(room.status==='waiting'&&room.updated_at<Date.now()-1200000){state.reason='expired';return commitRoom(room,state,'cancelled');}
  if(room.status==='active'&&state.deadline<Date.now()){
    if(state.orders.every(x=>!x)){state.reason='expired';return commitRoom(room,state,'cancelled');}
    const next=resolveRound(state);return commitRoom(room,next,next.winner||next.reason==='draw'?'finished':'active');
  }
  return room;
}
async function ownRoom(p:Player){
  const r=await gameDb().prepare('SELECT r.* FROM player_locks l JOIN rooms r ON r.code=l.room_code WHERE l.player_id=?').bind(p.id).first<Room>();
  return r?advance(r):null;
}
async function arena(req:Request,p:Player){
  const code=new URL(req.url).searchParams.get('code');
  const room=code?await readRoom(code):await ownRoom(p);
  const list=await gameDb().prepare("SELECT r.code,p.username,r.created_at AS createdAt FROM rooms r JOIN players p ON p.id=r.host_id WHERE r.status='waiting' AND json_extract(r.state,'$.inviteOnly') IS NULL AND r.host_id<>? AND r.updated_at>? ORDER BY r.created_at LIMIT 12").bind(p.id,Date.now()-1200000).all();
  return {room:room?visible(room,p):null,rooms:list.results};
}
async function createRoom(p:Player,inviteTo?:string){
  const locked=await ownRoom(p);if(locked&&['waiting','active'].includes(locked.status))throw new GameError('alreadyPlaying',409);
  const ids=await validateTeam(p,JSON.parse(p.team));
  const chars='ABCDEFGHJKLMNPQRSTUVWXYZ23456789',code=Array.from({length:6},()=>chars[Math.floor(random()*chars.length)]).join('');
  const now=Date.now(),state:Battle={inviteOnly:inviteTo,sides:[makeSide(p.id,p.username,ids)],round:1,orders:[null,null],deadline:now+1200000,logs:[],winner:null};
  try{await gameDb().batch([
    gameDb().prepare('INSERT INTO rooms (code,host_id,status,state,version,created_at,updated_at) VALUES (?,?,?,?,0,?,?)').bind(code,p.id,'waiting',JSON.stringify(state),now,now),
    gameDb().prepare('INSERT INTO player_locks (player_id,room_code) VALUES (?,?)').bind(p.id,code)
  ]);}catch(e){if(String(e).includes('UNIQUE'))throw new GameError('conflict',409);throw e;}
  return visible(await readRoom(code),p);
}
async function joinRoom(p:Player,code:unknown){
  const previous=await ownRoom(p);if(previous&&['active','waiting'].includes(previous.status))throw new GameError('alreadyPlaying',409);
  const r=await readRoom(typeof code==='string'?code.trim().toUpperCase():code);
  if(r.host_id===p.id||r.status!=='waiting'||r.updated_at<Date.now()-1200000)throw new GameError('roomUnavailable',409);
  const state=JSON.parse(r.state) as Battle;
  if(state.inviteOnly&&state.inviteOnly!==p.id)throw new GameError('ownership',403);
  state.sides.push(makeSide(p.id,p.username,await validateTeam(p,JSON.parse(p.team))));state.deadline=Date.now()+120000;
  try{
    const result=await gameDb().batch([
      gameDb().prepare("UPDATE rooms SET guest_id=?,status='active',state=?,version=version+1,updated_at=? WHERE code=? AND version=? AND status='waiting' AND guest_id IS NULL").bind(p.id,JSON.stringify(state),Date.now(),r.code,r.version),
      gameDb().prepare('INSERT INTO player_locks (player_id,room_code) SELECT ?,? WHERE EXISTS(SELECT 1 FROM rooms WHERE code=? AND guest_id=? AND version=?)').bind(p.id,r.code,r.code,p.id,r.version+1)
    ]);
    if(!result[0].meta.changes)throw new GameError('roomUnavailable',409);
  }catch(e){if(String(e).includes('UNIQUE'))throw new GameError('alreadyPlaying',409);throw e;}
  return visible(await readRoom(r.code),p);
}
async function arenaAction(p:Player,body:Record<string,unknown>){
  let r=await readRoom(body.code);visible(r,p);
  r=await advance(r);
  if(body.action==='sync'||['finished','cancelled'].includes(r.status))return visible(r,p);
  const state=JSON.parse(r.state) as Battle,side=state.sides.findIndex(x=>x.id===p.id);
  if(body.action==='cancel'&&r.status==='waiting'){state.reason='cancelled';return visible(await commitRoom(r,state,'cancelled'),p);}
  if(r.status!=='active')throw new GameError('roomUnavailable',409);
  if(body.action==='forfeit'){state.winner=state.sides[1-side].id;state.reason='forfeit';state.orders=[null,null];return visible(await commitRoom(r,state,'finished'),p);}
  if(body.action!=='order'||body.round!==state.round)throw new GameError('conflict',409);
  if(state.orders[side])return visible(r,p);
  const order=body.order as Order;
  if(!validOrder(state,side,order))throw new GameError('order');
  state.orders[side]=order;
  if(state.practice)state.orders[1-side]=practiceOrder(state);
  const next=state.orders.every(Boolean)?resolveRound(state):state;
  return visible(await commitRoom(r,next,next.winner||next.reason==='draw'?'finished':'active'),p);
}

async function createPractice(p:Player,difficulty:unknown){
  if(!['easy','normal','hard'].includes(String(difficulty)))throw new GameError('request');
  const locked=await ownRoom(p);if(locked&&['waiting','active'].includes(locked.status))throw new GameError('alreadyPlaying',409);
  const team=await validateTeam(p,JSON.parse(p.team));
  const ceiling=difficulty==='easy'?350:difficulty==='normal'?450:500;
  let pool=pokemon.filter(x=>!legendary(x.id)&&x.stats.reduce((a,b)=>a+b,0)<=ceiling);
  const ids:number[]=[];while(ids.length<3){const selected=choose(pool);ids.push(selected.id);pool=pool.filter(x=>x.id!==selected.id);}
  const chars='ABCDEFGHJKLMNPQRSTUVWXYZ23456789',code=Array.from({length:6},()=>chars[Math.floor(random()*chars.length)]).join('');
  const now=Date.now(),state:Battle={practice:difficulty as 'easy'|'normal'|'hard',sides:[makeSide(p.id,p.username,team),makeSide('practice-bot','Practice bot',ids)],round:1,orders:[null,null],deadline:now+120000,logs:[],winner:null};
  try{await gameDb().batch([gameDb().prepare('INSERT INTO rooms (code,host_id,status,state,version,created_at,updated_at) VALUES (?,?,?,?,0,?,?)').bind(code,p.id,'active',JSON.stringify(state),now,now),gameDb().prepare('INSERT INTO player_locks (player_id,room_code) VALUES (?,?)').bind(p.id,code)]);}catch(e){if(String(e).includes('UNIQUE'))throw new GameError('alreadyPlaying',409);throw e;}
  return visible(await readRoom(code),p);
}

export async function handleGame(req:Request):Promise<Response>{
  try{
    const path=new URL(req.url).pathname.replace(/^\/api\/game\//,''),db=gameDb();
    if(req.method==='GET'){
      if(path==='me'){const p=await session(req);return json({profile:p?await profile(p.id):null});}
      if(path==='arena')return json(await arena(req,await requirePlayer(req)));
      if(['club','ranking'].includes(path))return json(await extraGame(path,req,await requirePlayer(req),null,{profile,ownRoom,createRoom,joinRoom,roomView:async(p,code)=>visible(await readRoom(code),p)}));
      throw new GameError('request',404);
    }
    if(req.headers.get('Origin')!==gameConfig().origin)throw new GameError('origin',403);
    if(!req.headers.get('Content-Type')?.startsWith('application/json'))throw new GameError('request',415);
    if(Number(req.headers.get('Content-Length')||0)>8192)throw new GameError('request',413);
    const raw=await req.text();if(new TextEncoder().encode(raw).length>8192)throw new GameError('request',413);
    let body:Record<string,unknown>;try{body=JSON.parse(raw);if(!body||Array.isArray(body)||typeof body!=='object')throw new Error();}catch{throw new GameError('request');}
    const ip=req.headers.get('CF-Connecting-IP')||'unknown';
    if(path==='auth/register'||path==='auth/login'||path==='auth/recover'){
      await rate(req,'auth-ip',ip,50);
      const {username,password}=credentials(body,path!=='auth/login');
      await rate(req,`auth-${path}`,username,path==='auth/login'?10:5);
      const prehash=await keyed(`password:${password}`);
      const player=await db.prepare('SELECT * FROM players WHERE username=?').bind(username).first<Player>();
      if(path==='auth/register'){
        await rate(req,'registration-ip',ip,8,3600000);
        if(player)throw new GameError('taken',409,'username');
        if(![1,4,7].includes(Number(body.starter)))throw new GameError('starter',400,'starter');
        const starter=Number(body.starter),pool=common().filter(p=>p.id!==starter&&![1,4,7].includes(p.id));
        const first=choose(pool),second=choose(pool.filter(x=>x.id!==first.id)),team=[starter,first.id,second.id],id=crypto.randomUUID(),recovery=token(),sessionToken=token(),now=Date.now();
        const passwordHash=await bcrypt.hash(prehash,12),recoveryHash=await keyed(`recovery:${recovery}`);
        try{await db.batch([
          db.prepare('INSERT INTO players (id,username,password_hash,recovery_hash,created_at,team) VALUES (?,?,?,?,?,?)').bind(id,username,passwordHash,recoveryHash,now,JSON.stringify(team)),
          ...team.map(card=>db.prepare('INSERT INTO cards (player_id,pokemon_id,source,created_at) VALUES (?,?,?,?)').bind(id,card,'starter',now)),
          db.prepare('INSERT INTO sessions (token_hash,player_id,expires_at) VALUES (?,?,?)').bind(await digest(sessionToken),id,now+DAY*7)
        ]);}catch(e){if(String(e).includes('UNIQUE'))throw new GameError('taken',409,'username');throw e;}
        return json({profile:await profile(id),recoveryCode:recovery},201,cookie(sessionToken));
      }
      if(path==='auth/login'){
        const valid=player?await bcrypt.compare(prehash,player.password_hash):await bcrypt.hash(prehash,12).then(()=>false);
        if(!valid||!player)throw new GameError('credentials',401);
        return json({profile:await profile(player.id)},200,cookie(await newSession(player.id)));
      }
      if(typeof body.recoveryCode!=='string'||!player||player.recovery_hash!==await keyed(`recovery:${body.recoveryCode}`))throw new GameError('recovery',401,'recoveryCode');
      const recovery=token(),sessionToken=token();
      const result=await db.batch([
        db.prepare('UPDATE players SET password_hash=?,recovery_hash=?,version=version+1 WHERE id=? AND recovery_hash=?').bind(await bcrypt.hash(prehash,12),await keyed(`recovery:${recovery}`),player.id,player.recovery_hash),
        db.prepare('DELETE FROM sessions WHERE player_id=? AND EXISTS(SELECT 1 FROM players WHERE id=? AND recovery_hash=?)').bind(player.id,player.id,await keyed(`recovery:${recovery}`)),
        db.prepare('INSERT INTO sessions (token_hash,player_id,expires_at) SELECT ?,?,? WHERE EXISTS(SELECT 1 FROM players WHERE id=? AND recovery_hash=?)').bind(await digest(sessionToken),player.id,Date.now()+DAY*7,player.id,await keyed(`recovery:${recovery}`))
      ]);
      if(!result[0].meta.changes)throw new GameError('recovery',401);
      return json({profile:await profile(player.id),recoveryCode:recovery},200,cookie(sessionToken));
    }
    if(path==='auth/logout'){const t=cookieToken(req);if(t)await db.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await digest(t)).run();return json({profile:null},200,cookie('',0));}
    const p=await requirePlayer(req);await rate(req,'game',p.id,120,60000);
    if(path==='auth/recovery-code'){
      if(typeof body.password!=='string'||body.password.length>128||!await bcrypt.compare(await keyed(`password:${body.password}`),p.password_hash))throw new GameError('credentials',401,'password');
      const recovery=token();await db.prepare('UPDATE players SET recovery_hash=? WHERE id=?').bind(await keyed(`recovery:${recovery}`),p.id).run();return json({recoveryCode:recovery});
    }
    if(path==='team'){const ids=await validateTeam(p,body.team);await db.prepare('UPDATE players SET team=?,version=version+1 WHERE id=?').bind(JSON.stringify(ids),p.id).run();return json({profile:await profile(p.id)});}
    if(path==='expedition'||path==='pack')return json({reward:await acquisition(p,body,path),profile:await profile(p.id)});
    if(path==='arena/create')return json({room:await createRoom(p)});
    if(path==='arena/practice')return json({room:await createPractice(p,body.difficulty)});
    const extra=await extraGame(path,req,p,body,{profile,ownRoom,createRoom,joinRoom,roomView:async(p,code)=>visible(await readRoom(code),p)});if(extra!==undefined)return json(extra);
    if(path==='arena/join')return json({room:await joinRoom(p,body.code)});
    if(path==='arena/action')return json({room:await arenaAction(p,body),profile:await profile(p.id)});
    throw new GameError('request',404);
  }catch(e){
    if(e instanceof GameError)return json({error:e.code,field:e.field},e.status);
    console.error('Game request failed',e instanceof Error?e.message:'Storage error');
    return json({error:'unavailable'},503);
  }
}
