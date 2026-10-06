import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
let database: ReturnType<typeof openGameDatabase>;
export function openGameDatabase(path: string, migrations: string) {
  const sqlite = new DatabaseSync(path);
  sqlite.exec('PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;');
  sqlite.exec('CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, sha256 TEXT NOT NULL)');
  for (const name of readdirSync(migrations).filter(x=>x.endsWith('.sql')).sort()) {
    const sql=readFileSync(`${migrations}/${name}`,'utf8'), hash=createHash('sha256').update(sql).digest('hex');
    const applied=sqlite.prepare('SELECT sha256 FROM schema_migrations WHERE name=?').get(name);
    if(applied){if(applied.sha256!==hash)throw new Error('An applied migration was modified');continue;}
    sqlite.exec('BEGIN IMMEDIATE');
    try { sqlite.exec(sql);sqlite.prepare('INSERT INTO schema_migrations VALUES (?,?)').run(name,hash);sqlite.exec('COMMIT'); }
    catch(e){sqlite.exec('ROLLBACK');sqlite.close();throw e;}
  }
  class Statement {
    constructor(public sql:string,public args:unknown[]=[]){}
    bind(...args:unknown[]){return new Statement(this.sql,args);}
    first<T>(column?:string):Promise<T|null>{const value=sqlite.prepare(this.sql).get(...this.args as never[])||null;return Promise.resolve((column&&value?value[column]:value) as T|null);}
    all<T>():Promise<{results:T[]}>{return Promise.resolve({results:sqlite.prepare(this.sql).all(...this.args as never[]) as T[]});}
    execute(){const result=sqlite.prepare(this.sql).run(...this.args as never[]);return {success:true,results:[],meta:{changes:Number(result.changes),last_row_id:Number(result.lastInsertRowid)}};}
    run(){return Promise.resolve(this.execute());}
  }
  return {sqlite,prepare:(sql:string)=>new Statement(sql),batch:async(statements:Statement[])=>{
    sqlite.exec('BEGIN IMMEDIATE');
    try {const result=statements.map(s=>s.execute());sqlite.exec('COMMIT');return result;}
    catch(e){sqlite.exec('ROLLBACK');throw e;}
  }};
}
export function initGameDatabase(path:string,migrations:string){database=openGameDatabase(path,migrations);return database;}
export function gameDb(){if(!database)throw new Error('Game database is unavailable');return database;}
export function gameConfig(){
  const pepper=process.env.AUTH_PEPPER,origin=process.env.SITE_ORIGIN;
  if(!pepper||pepper.length<32||!origin||!/^https:\/\/[a-z0-9.-]+$/.test(origin))throw new Error('Game authentication is unavailable');
  return {pepper,origin};
}
