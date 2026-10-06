import {createRequire} from 'node:module';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {mkdirSync,copyFileSync,readdirSync,realpathSync,readFileSync,writeFileSync} from 'node:fs';
const root=dirname(fileURLToPath(import.meta.url));
const dependencies=process.env.POKEHABITAT_DEPENDENCIES||root;
const require=createRequire(resolve(dependencies,'package.json'));
let esbuild;try{esbuild=require('esbuild');}catch{esbuild=createRequire(realpathSync(resolve(dependencies,'node_modules/wrangler/package.json')))('esbuild');}
mkdirSync(resolve(root,'server/dist/migrations'),{recursive:true});
await esbuild.build({entryPoints:[resolve(root,'server/source/main.ts')],outfile:resolve(root,'server/dist/server.mjs'),bundle:true,format:'esm',platform:'node',target:'node24',nodePaths:[resolve(dependencies,'node_modules')],logLevel:'info'});
for(const name of readdirSync(resolve(root,'server/migrations')).filter(x=>x.endsWith('.sql')))copyFileSync(resolve(root,'server/migrations',name),resolve(root,'server/dist/migrations',name));
writeFileSync(resolve(root,'server/dist/LICENSE-bcryptjs'),readFileSync(resolve(dependencies,'node_modules/bcryptjs/LICENSE'),'utf8').replaceAll('\r\n','\n'));
