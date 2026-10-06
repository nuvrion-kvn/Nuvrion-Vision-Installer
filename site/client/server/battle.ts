import { byId, type Move } from '../lib/pokemon';
import chartData from '../data/type-chart.json';
const chart = chartData as Record<string, Record<string, number>>;
export type Order = { kind: 'attack' | 'switch' | 'pass'; index: number };
export type Fighter = { id: number; formId: number; hp: number; maxHp: number; pp: number[] };
export type Side = { id: string; username: string; team: Fighter[]; active: number };
export type BattleEvent = { id: string; round: number; kind: 'attack'|'switch'|'transform'|'faint'|'pass'|'end'; actor: number; pokemonId?: number; targetId?: number; move?: Move; damage?: number; effectiveness?: number; miss?: boolean };
export type Battle = { inviteOnly?: string; practice?: 'easy'|'normal'|'hard'; sides: Side[]; round: number; orders: (Order|null)[]; deadline: number; logs: BattleEvent[]; winner: string|null; reason?: string };
export function random() { return crypto.getRandomValues(new Uint32Array(1))[0] / 4294967296; }
export function choose<T>(items: T[], rng = random): T { if (!items.length) throw new Error('Empty reward pool'); return items[Math.floor(rng()*items.length)]; }
export function makeSide(id: string, username: string, ids: number[]): Side {
  return { id, username, active: 0, team: ids.map(id => { const p = byId.get(id)!; return { id, formId: id, hp: p.stats[0]+60, maxHp: p.stats[0]+60, pp: p.moves.map(m => m.pp || 15) }; }) };
}
export function active(side: Side) { return side.team[side.active]; }
export function fighterMoves(fighter: Fighter) { return byId.get(fighter.formId)!.moves; }
export const struggle: Move = { id:165,slug:'struggle',name:{ru:'Борьба',en:'Struggle'},description:{ru:'Последняя атака с отдачей, когда нет PP.',en:'A last-resort attack with recoil when PP is depleted.'},type:'normal',power:50,accuracy:null,pp:1,priority:0,damageClass:'physical' };
export function availableMoves(fighter: Fighter) { return fighter.pp.every(n=>n===0) ? [struggle] : fighterMoves(fighter); }
export function validOrder(state: Battle, side: number, order: Order) {
  if (!order || !Number.isInteger(order.index)) return false;
  const player = state.sides[side];
  if (order.kind === 'switch') return order.index >= 0 && order.index < player.team.length && order.index !== player.active && player.team[order.index].hp > 0;
  if (order.kind === 'attack') return order.index >= 0 && order.index < availableMoves(active(player)).length && (active(player).pp.every(n=>n===0) || active(player).pp[order.index]>0);
  return false;
}
export function typeMultiplier(type: string, defenders: string[]) { return defenders.reduce((m,t)=>m*(chart[type]?.[t]??1),1); }
export function movePower(attacker: Fighter, defender: Fighter, move: Move) {
  if(move.id===67){const weight=byId.get(defender.formId)!.weight;return weight<10?20:weight<25?40:weight<50?60:weight<100?80:weight<200?100:120;}
  if(move.id===175){const ratio=Math.floor(64*attacker.hp/attacker.maxHp);return ratio<=1?200:ratio<=5?150:ratio<=12?100:ratio<=21?80:ratio<=42?40:20;}
  return move.power??60;
}
export function calculateDamage(attacker: Fighter, defender: Fighter, move: Move, rng=random) {
  const a=byId.get(attacker.formId)!, d=byId.get(defender.formId)!;
  const special = move.damageClass === 'special';
  const power = movePower(attacker,defender,move);
  const effectiveness = move.id===165 ? 1 : typeMultiplier(move.type,d.types);
  if (effectiveness===0) return { damage:0, effectiveness };
  if(move.id===82)return {damage:40,effectiveness:1};
  const base = Math.floor(Math.floor(22*power*(a.stats[special?3:1]+5)/(d.stats[special?4:2]+5))/50)+2;
  const stab = move.id!==165 && a.types.includes(move.type) ? 1.5 : 1;
  return { damage:Math.max(1,Math.floor(base*stab*effectiveness*(.85+rng()*.15))), effectiveness };
}
export function resolveRound(input: Battle, rng=random, now=Date.now()): Battle {
  const s = structuredClone(input);
  const event=(value:Omit<BattleEvent,'id'|'round'>)=>s.logs.push({...value,id:crypto.randomUUID(),round:s.round});
  const starting=s.sides.map(x=>x.active);
  const priority=(i:number)=>{ const o=s.orders[i]; if(o?.kind==='switch')return 6; if(o?.kind==='attack')return availableMoves(active(s.sides[i]))[o.index]?.priority??0; return -10; };
  const speed=(i:number)=>byId.get(active(s.sides[i]).formId)!.stats[5];
  const order=[0,1].sort((a,b)=>priority(b)-priority(a)||speed(b)-speed(a)||(rng()<.5?-1:1));
  for (const i of order) {
    if(s.winner)break;
    const side=s.sides[i], enemy=s.sides[1-i], command=s.orders[i];
    if(!command || command.kind==='pass'){event({kind:'pass',actor:i});continue;}
    if(command.kind==='switch') { if(side.team[command.index].hp>0){side.active=command.index;event({kind:'switch',actor:i,pokemonId:active(side).formId});} continue; }
    if(side.active!==starting[i] || active(side).hp<=0)continue;
    const actor=active(side), target=active(enemy), moves=availableMoves(actor), move=moves[command.index];
    if(!move)continue;
    const exhausted=actor.pp.every(n=>n===0);
    if(!exhausted){if(actor.pp[command.index]<=0)continue;actor.pp[command.index]--;}
    if(move.slug==='transform' || move.id===144) {
      actor.formId=target.formId;actor.pp=fighterMoves(target).map(()=>5);
      event({kind:'transform',actor:i,pokemonId:actor.id,targetId:target.formId,move});continue;
    }
    const miss=move.accuracy!==null && rng()*100>=move.accuracy;
    const result=miss?{damage:0,effectiveness:1}:calculateDamage(actor,target,move,rng);
    const damage=Math.min(target.hp,result.damage);target.hp-=damage;
    event({kind:'attack',actor:i,pokemonId:actor.formId,targetId:target.formId,move,damage,effectiveness:result.effectiveness,miss});
    if(!miss&&move.meta?.drain&&damage>0)actor.hp=Math.min(actor.maxHp,Math.max(0,actor.hp+Math.ceil(damage*move.meta.drain/100)));
    if(move.id===165)actor.hp=Math.max(0,actor.hp-Math.max(1,Math.floor(actor.maxHp/4)));
    for(const j of [1-i,i]){const x=s.sides[j];if(active(x).hp===0){event({kind:'faint',actor:j,pokemonId:active(x).formId});const next=x.team.findIndex(p=>p.hp>0);if(next>=0)x.active=next;}}
    const alive=s.sides.map(x=>x.team.some(p=>p.hp>0));
    if(!alive[0] || !alive[1]) { s.winner=alive[0]?s.sides[0].id:alive[1]?s.sides[1].id:null;s.reason=alive.some(Boolean)?'knockout':'draw';event({kind:'end',actor:alive[0]?0:1});break; }
  }
  s.logs=s.logs.slice(-40);s.orders=[null,null];s.round++;s.deadline=now+120000;return s;
}
