import { createServer } from 'node:http';
import { chmodSync, lstatSync, unlinkSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { handleGame } from './server/game-service';
import { initGameDatabase, gameConfig } from './db/game';
export {handleGame,initGameDatabase};
export function createGameServer(){
  const {origin}=gameConfig();
  return createServer({maxHeaderSize:16384},async(req,res)=>{
    const reply=(status:number,error:string)=>{res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(JSON.stringify({error}));};
    try{
      if(!req.url?.startsWith('/api/game/')||req.url.startsWith('//'))return reply(404,'request');
      if(!['GET','POST'].includes(req.method||''))return reply(405,'request');
      if(Number(req.headers['content-length']||0)>8192)return reply(413,'request');
      const chunks:Buffer[]=[];let size=0;
      for await(const chunk of req){size+=chunk.length;if(size>8192){reply(413,'request');req.destroy();return;}chunks.push(chunk);}
      const headers=new Headers();for(const [key,value] of Object.entries(req.headers))if(value)headers.set(key,Array.isArray(value)?value.join(','):value);
      const request=new Request(origin+req.url,{method:req.method,headers,...(req.method==='POST'?{body:Buffer.concat(chunks)}:{})});
      const response=await handleGame(request);
      res.writeHead(response.status,Object.fromEntries(response.headers));res.end(Buffer.from(await response.arrayBuffer()));
    }catch{if(!res.headersSent)reply(503,'unavailable');else res.end();}
  });
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
  const root=dirname(fileURLToPath(import.meta.url));
  initGameDatabase(process.env.GAME_DB||'/var/lib/nuvrion-pokehabitat/game.sqlite',join(root,'migrations'));
  const socket=process.env.GAME_SOCKET||'/run/nuvrion-pokehabitat/game.sock';
  try{if(!lstatSync(socket).isSocket())throw new Error('Game socket path is occupied');unlinkSync(socket);}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}
  const server=createGameServer();server.requestTimeout=15000;server.headersTimeout=10000;
  server.listen(socket,()=>{chmodSync(socket,0o660);console.log('PokéHabitat is ready on its local Unix socket');});
  const stop=()=>{server.close(()=>process.exit(0));setTimeout(()=>process.exit(1),5000).unref();};
  process.on('SIGTERM',stop);process.on('SIGINT',stop);
}
