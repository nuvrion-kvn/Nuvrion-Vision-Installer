import { gameDb } from '../db/game';
import { byId } from '../lib/pokemon';
import { GameError } from './game-errors';
import { active, availableMoves, calculateDamage, random, type Battle, type Order } from './battle';
import type { Player } from './game-service';
const DAY=86400000;
const covers=['forest','water','mountain','grassland','cave','urban','unknown'];
type Trainer={player_id:string;avatar:number;cover:string;favorites:string;xp:number;pve_wins:number;evolutions:number};
type Context={profile:(id:string)=>Promise<unknown>;ownRoom:(p:Player)=>Promise<{code:string;status:string;host_id:string;state:string}|null>;createRoom:(p:Player,inviteTo?:string)=>Promise<{code:string}>;roomView:(p:Player,code:string)=>Promise<{code:string}>;joinRoom:(p:Player,code:unknown)=>Promise<unknown>};
export async function trainerDetails(p:Player,cards:{id:number}[]){
 const db=gameDb();await db.prepare('INSERT OR IGNORE INTO trainer_profiles (player_id,avatar) VALUES (?,?)').bind(p.id,cards[0]?.id||25).run();
 const t=(await db.prepare('SELECT * FROM trainer_profiles WHERE player_id=?').bind(p.id).first<Trainer>())!;
 const xp=t.xp+p.wins*40+p.losses*10+cards.length*10;
 return {trainer:{avatar:t.avatar,cover:t.cover,favorites:JSON.parse(t.favorites) as number[],xp,level:1+Math.floor(xp/100),pveWins:t.pve_wins,evolutions:t.evolutions}};
}
export function practiceOrder(state:Battle):Order{
 const bot=state.sides[1],enemy=state.sides[0],fighter=active(bot),target=active(enemy),moves=availableMoves(fighter);
 const valid=moves.map((m,i)=>({m,i})).filter(x=>fighter.pp.every(n=>n===0)||fighter.pp[x.i]>0);
 if(state.practice==='easy'||state.practice==='normal'&&random()<.25)return {kind:'attack',index:valid[Math.floor(random()*valid.length)].i};
 const score=(form:typeof fighter)=>Math.max(...availableMoves(form).filter((m,i)=>form.pp.every(n=>n===0)||form.pp[i]>0).map(m=>m.id===144?20:calculateDamage(form,target,m,()=>1).damage*(m.accuracy??100)/100));
 if(state.practice==='hard'&&score(fighter)===0){const i=bot.team.findIndex((f,i)=>i!==bot.active&&f.hp>0&&score(f)>0);if(i>=0)return {kind:'switch',index:i};}
 valid.sort((a,b)=>calculateDamage(fighter,target,b.m,()=>1).damage*(b.m.accuracy??100)-calculateDamage(fighter,target,a.m,()=>1).damage*(a.m.accuracy??100));
 return {kind:'attack',index:valid[0].i};
}
function seasonBounds(offset=0){const d=new Date(),start=Date.UTC(d.getUTCFullYear(),d.getUTCMonth()+offset,1),end=Date.UTC(d.getUTCFullYear(),d.getUTCMonth()+offset+1,1);return {id:new Date(start).toISOString().slice(0,7),start:Math.floor(start/DAY),end:Math.floor(end/DAY),endsAt:end};}
async function ranking(offset=0){
 const season=seasonBounds(offset);
 const rows=await gameDb().prepare(`SELECT p.id,p.username,COALESCE(t.avatar,25) AS avatar,SUM(CASE WHEN b.won=1 THEN 1 ELSE 0 END) AS wins,SUM(CASE WHEN b.won=0 THEN 1 ELSE 0 END) AS losses,MAX(0,SUM(CASE WHEN b.won=1 THEN 25 WHEN b.won=0 THEN -10 ELSE 0 END)) AS points FROM battle_rewards b JOIN players p ON p.id=b.player_id LEFT JOIN trainer_profiles t ON t.player_id=p.id WHERE b.day>=? AND b.day<? AND b.won>=0 GROUP BY p.id ORDER BY points DESC,wins DESC,p.created_at LIMIT 50`).bind(season.start,season.end).all<{id:string;username:string;avatar:number;wins:number;losses:number;points:number}>();
 return {season,players:rows.results.map((r,i)=>({...r,rank:i+1,league:r.points>=500?'legend':r.points>=250?'gold':r.points>=100?'silver':'bronze'}))};
}
async function tasks(p:Player){
 const db=gameDb(),day=Math.floor(Date.now()/DAY),cards=(await db.prepare('SELECT COUNT(*) AS n FROM cards WHERE player_id=?').bind(p.id).first<{n:number}>())!.n;
 const t=(await db.prepare('SELECT * FROM trainer_profiles WHERE player_id=?').bind(p.id).first<Trainer>())!;
 const expedition=!!await db.prepare("SELECT id FROM claims WHERE player_id=? AND kind='expedition' AND created_at>=?").bind(p.id,day*DAY).first();
 const duel=!!await db.prepare('SELECT room_code FROM battle_rewards WHERE player_id=? AND day=? AND won>=0').bind(p.id,day).first();
 const practice=!!await db.prepare('SELECT room_code FROM practice_results WHERE player_id=? AND day=? AND won=1').bind(p.id,day).first();
 const definitions=[{id:`daily:${day}:explore`,name:'explore',done:expedition,coins:20,xp:25,daily:true},{id:`daily:${day}:duel`,name:'duel',done:duel,coins:25,xp:30,daily:true},{id:`daily:${day}:practice`,name:'practice',done:practice,coins:20,xp:25,daily:true},{id:'achievement:collector',name:'collector',done:cards>=10,coins:60,xp:50,daily:false},{id:'achievement:winner',name:'winner',done:p.wins>=1,coins:50,xp:50,daily:false},{id:'achievement:veteran',name:'veteran',done:p.wins>=10,coins:150,xp:100,daily:false},{id:'achievement:evolve',name:'evolve',done:t.evolutions>=1,coins:50,xp:50,daily:false},{id:'achievement:practice',name:'botmaster',done:t.pve_wins>=3,coins:60,xp:50,daily:false}];
 const claims=await db.prepare("SELECT id FROM claims WHERE player_id=? AND kind='task'").bind(p.id).all<{id:string}>();
 return definitions.map(t=>({...t,claimed:claims.results.some(c=>c.id===`${p.id}:${t.id}`)}));
}
async function rewardClaim(p:Player,id:string,kind:string,coins:number,xp:number){
 const db=gameDb(),nonce=crypto.randomUUID();
 const result=await db.batch([
  db.prepare('UPDATE players SET credits=credits+?,version=version+1,last_operation=? WHERE id=? AND version=? AND NOT EXISTS(SELECT 1 FROM claims WHERE id=?)').bind(coins,nonce,p.id,p.version,id),
  db.prepare('INSERT INTO claims (id,player_id,kind,result,created_at) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM players WHERE id=? AND last_operation=?)').bind(id,p.id,kind,JSON.stringify({coins,xp}),Date.now(),p.id,nonce),
  db.prepare('UPDATE trainer_profiles SET xp=xp+? WHERE player_id=? AND EXISTS(SELECT 1 FROM players WHERE id=? AND last_operation=?)').bind(xp,p.id,p.id,nonce)
 ]);
 if(!result[0].meta.changes){if(await db.prepare('SELECT id FROM claims WHERE id=?').bind(id).first())return;throw new GameError('conflict',409);}
}
async function social(p:Player){
 const db=gameDb();
 const friends=await db.prepare(`SELECT CASE WHEN f.a=? THEN f.b ELSE f.a END AS id,p.username,COALESCE(t.avatar,25) AS avatar,f.status,f.requester FROM friendships f JOIN players p ON p.id=CASE WHEN f.a=? THEN f.b ELSE f.a END LEFT JOIN trainer_profiles t ON t.player_id=p.id WHERE f.a=? OR f.b=? ORDER BY f.created_at DESC`).bind(p.id,p.id,p.id,p.id).all();
 const invites=await db.prepare(`SELECT i.id,i.room_code AS code,p.username,i.sender,i.receiver FROM duel_invites i JOIN players p ON p.id=i.sender JOIN rooms r ON r.code=i.room_code WHERE i.receiver=? AND i.status='pending' AND i.expires_at>? AND r.status='waiting'`).bind(p.id,Date.now()).all();
 return {friends:friends.results,invites:invites.results};
}
export async function extraGame(path:string,req:Request,p:Player,body:Record<string,unknown>|null,c:Context):Promise<unknown|undefined>{
 const db=gameDb();
 if(path==='ranking')return ranking();
 if(path==='club'){
  await trainerDetails(p,[]);
  const current=await ranking(),previous=await ranking(-1),rank=previous.players.find(x=>x.id===p.id);
  const coins=rank&&rank.points>0?(rank.rank===1?300:rank.rank<=3?200:rank.rank<=10?100:0):0;
  const claimed=!!await db.prepare('SELECT id FROM claims WHERE id=?').bind(`${p.id}:season:${previous.season.id}`).first();
  return {...await social(p),tasks:await tasks(p),ranking:current,seasonReward:{id:previous.season.id,coins,claimed}};
 }
 if(!body)return undefined;
 if(path==='trainer'){
  const owned=await db.prepare('SELECT pokemon_id AS id FROM cards WHERE player_id=?').bind(p.id).all<{id:number}>();
  if(!Number.isInteger(body.avatar)||!owned.results.some(x=>x.id===body.avatar)||!covers.includes(String(body.cover))||!Array.isArray(body.favorites)||body.favorites.length>3||new Set(body.favorites).size!==body.favorites.length||body.favorites.some(id=>!owned.results.some(x=>x.id===id)))throw new GameError('request');
  await trainerDetails(p,owned.results);
  await db.batch([db.prepare('UPDATE trainer_profiles SET avatar=?,cover=?,favorites=? WHERE player_id=?').bind(body.avatar,String(body.cover),JSON.stringify(body.favorites),p.id),db.prepare('UPDATE players SET version=version+1 WHERE id=?').bind(p.id)]);
  return {profile:await c.profile(p.id)};
 }
 if(path==='evolve'){
  const from=Number(body.from),to=Number(body.to),mon=byId.get(from);
  if(typeof body.key!=='string'||!/^[a-f0-9-]{36}$/i.test(body.key))throw new GameError('request');
  const id=`${p.id}:evolve:${body.key}`,previous=await db.prepare('SELECT result FROM claims WHERE id=?').bind(id).first<{result:string}>();
  if(previous){const reward=JSON.parse(previous.result);if(reward.fromId!==from||reward.pokemonId!==to)throw new GameError('request');return {reward,profile:await c.profile(p.id)};}
  if(!mon?.evolution.edges.some(e=>e.from===from&&e.to===to)||!byId.has(to))throw new GameError('evolution');
  if(!await db.prepare('SELECT pokemon_id FROM cards WHERE player_id=? AND pokemon_id=?').bind(p.id,from).first())throw new GameError('ownership',403);
  if(await db.prepare('SELECT pokemon_id FROM cards WHERE player_id=? AND pokemon_id=?').bind(p.id,to).first())throw new GameError('owned',409);
  if(p.credits<150)throw new GameError('evolveCoins',409);

  await trainerDetails(p,[]);const nonce=crypto.randomUUID(),reward={pokemonId:to,fromId:from,duplicate:false,coins:0,kind:'evolution'};
  const result=await db.batch([
   db.prepare('UPDATE players SET credits=credits-150,version=version+1,last_operation=? WHERE id=? AND version=? AND credits>=150 AND NOT EXISTS(SELECT 1 FROM cards WHERE player_id=? AND pokemon_id=?) AND NOT EXISTS(SELECT 1 FROM claims WHERE id=?)').bind(nonce,p.id,p.version,p.id,to,id),
   db.prepare('INSERT INTO claims (id,player_id,kind,result,created_at) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM players WHERE id=? AND last_operation=?)').bind(id,p.id,'evolution',JSON.stringify(reward),Date.now(),p.id,nonce),
   db.prepare("INSERT INTO cards (player_id,pokemon_id,source,created_at) SELECT ?,?,'evolution',? WHERE EXISTS(SELECT 1 FROM players WHERE id=? AND last_operation=?)").bind(p.id,to,Date.now(),p.id,nonce),
   db.prepare('UPDATE trainer_profiles SET evolutions=evolutions+1,xp=xp+30 WHERE player_id=? AND EXISTS(SELECT 1 FROM players WHERE id=? AND last_operation=?)').bind(p.id,p.id,nonce)
  ]);
  if(!result[0].meta.changes)throw new GameError('conflict',409);
  return {reward,profile:await c.profile(p.id)};
 }
 if(path==='task/claim'){
  await trainerDetails(p,[]);const task=(await tasks(p)).find(t=>t.id===body.id);
  if(!task?.done)throw new GameError('task',409);
  await rewardClaim(p,`${p.id}:${task.id}`,'task',task.coins,task.xp);
  return {profile:await c.profile(p.id)};
 }
 if(path==='season/claim'){
  const previous=await ranking(-1),rank=previous.players.find(r=>r.id===p.id),coins=rank&&rank.points>0?(rank.rank===1?300:rank.rank<=3?200:rank.rank<=10?100:0):0;
  if(!coins)throw new GameError('task',409);await trainerDetails(p,[]);
  await rewardClaim(p,`${p.id}:season:${previous.season.id}`,'season',coins,0);return {profile:await c.profile(p.id)};
 }
 if(path==='friends/request'){
  if(typeof body.username!=='string'||!/^[a-zA-Z0-9_]{3,20}$/.test(body.username))throw new GameError('username',400,'username');
  const friend=await db.prepare('SELECT id FROM players WHERE username=?').bind(body.username.toLowerCase()).first<{id:string}>();
  if(!friend||friend.id===p.id)throw new GameError('friend');const [a,b]=[p.id,friend.id].sort();
  const count=await db.prepare('SELECT COUNT(*) AS n FROM friendships WHERE a=? OR b=?').bind(p.id,p.id).first<{n:number}>();if(count!.n>=100)throw new GameError('friendLimit',409);
  await db.prepare("INSERT OR IGNORE INTO friendships (a,b,requester,status,created_at) VALUES (?,?,?,'pending',?)").bind(a,b,p.id,Date.now()).run();return {profile:await c.profile(p.id)};
 }
 if(path==='friends/action'){
  if(typeof body.id!=='string')throw new GameError('request');const [a,b]=[p.id,body.id].sort();
  if(body.action==='accept'){const r=await db.prepare("UPDATE friendships SET status='accepted' WHERE a=? AND b=? AND requester<>? AND status='pending'").bind(a,b,p.id).run();if(!r.meta.changes)throw new GameError('friend');}
  else if(body.action==='remove')await db.prepare('DELETE FROM friendships WHERE a=? AND b=?').bind(a,b).run();else throw new GameError('request');
  return {profile:await c.profile(p.id)};
 }
 if(path==='friends/invite'){
  if(typeof body.id!=='string')throw new GameError('request');const [a,b]=[p.id,body.id].sort();
  if(!await db.prepare("SELECT a FROM friendships WHERE a=? AND b=? AND status='accepted'").bind(a,b).first())throw new GameError('friend');
  const existing=await c.ownRoom(p);if(existing&&['waiting','active'].includes(existing.status)&&!(existing.status==='waiting'&&JSON.parse(existing.state).inviteOnly===body.id))throw new GameError('alreadyPlaying',409);
  const room=existing?.status==='waiting'?await c.roomView(p,existing.code):await c.createRoom(p,body.id);
  await db.prepare('INSERT OR IGNORE INTO duel_invites (id,sender,receiver,room_code,created_at,expires_at) VALUES (?,?,?,?,?,?)').bind(`${p.id}:${room.code}`,p.id,body.id,room.code,Date.now(),Date.now()+1200000).run();
  return {room,profile:await c.profile(p.id)};
 }
 if(path==='friends/accept-invite'){
  const invite=await db.prepare("SELECT * FROM duel_invites WHERE id=? AND receiver=? AND status IN ('pending','accepted') AND expires_at>?").bind(String(body.id),p.id,Date.now()).first<{room_code:string}>();
  if(!invite)throw new GameError('roomUnavailable',409);const existing=await c.ownRoom(p);const room=existing?.code===invite.room_code?await c.roomView(p,invite.room_code):await c.joinRoom(p,invite.room_code);
  await db.prepare("UPDATE duel_invites SET status='accepted' WHERE id=? AND receiver=?").bind(String(body.id),p.id).run();return {room,profile:await c.profile(p.id)};
 }
 if(path==='friends/decline-invite'){await db.prepare("UPDATE duel_invites SET status='declined' WHERE id=? AND receiver=?").bind(String(body.id),p.id).run();return {profile:await c.profile(p.id)};}
 return undefined;
}
