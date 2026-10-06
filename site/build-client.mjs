#!/usr/bin/env node
// Offline after dependency installation. No source or asset is fetched at build time.
import { createRequire } from 'node:module';
import { lstat, symlink, unlink, readFile, readdir, copyFile, writeFile } from 'node:fs/promises';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const siteRoot = dirname(fileURLToPath(import.meta.url));
const clientRoot = join(siteRoot, 'client');
const dependencyRoot = resolve(process.argv[2] || process.env.POKEHABITAT_NODE_MODULES || join(process.env.POKEHABITAT_DEPENDENCIES || siteRoot, 'node_modules'));
const dependencyRequire = createRequire(join(dependencyRoot, '../package.json'));
const { build } = await import(pathToFileURL(dependencyRequire.resolve('vite')).href);
const tailwind = (await import(pathToFileURL(dependencyRequire.resolve('@tailwindcss/postcss')).href)).default;
const temporaryLink = join(clientRoot, 'node_modules');
let linked = false;
try {
  try {
    await lstat(temporaryLink);
    throw new Error('client/node_modules must be absent; install build dependencies in site/node_modules or pass its path.');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  await symlink(dependencyRoot, temporaryLink, 'dir');
  linked = true;
  const ts = dependencyRequire('typescript');
  const tsconfig = ts.readConfigFile(join(clientRoot, 'tsconfig.json'), ts.sys.readFile);
  if (tsconfig.error) throw new Error(ts.flattenDiagnosticMessageText(tsconfig.error.messageText, '\n'));
  const parsed = ts.parseJsonConfigFileContent(tsconfig.config, ts.sys, clientRoot);
  const program = ts.createProgram(parsed.fileNames, parsed.options);
  const diagnostics = ts.getPreEmitDiagnostics(program);
  if (diagnostics.length) throw new Error(ts.formatDiagnosticsWithColorAndContext(diagnostics, {
    getCanonicalFileName: filename => filename,
    getCurrentDirectory: () => clientRoot,
    getNewLine: () => '\n',
  }));
  console.log('TypeScript: all client sources passed.');
  await build({
    configFile: false,
    root: clientRoot,
    publicDir: join(siteRoot, 'public'),
    resolve: { alias: { '@': clientRoot } },
    oxc: { jsx: { runtime: 'automatic', importSource: 'react' } },
    css: { postcss: { plugins: [tailwind({ base: clientRoot, optimize: true })] } },
    build: {
      outDir: join(siteRoot, 'dist'),
      emptyOutDir: true,
      target: 'es2022',
      sourcemap: false,
      minify: 'oxc',
      reportCompressedSize: false,
      chunkSizeWarningLimit: 800,
      license: { fileName: 'DEPENDENCIES.md' },
    },
  });
  await copyFile(join(siteRoot, 'LICENSES.md'), join(siteRoot, 'dist/LICENSES.md'));
  const notices = join(siteRoot, 'dist/DEPENDENCIES.md');
  await writeFile(notices, (await readFile(notices, 'utf8')).replaceAll('\r\n', '\n'));
  const html = await readFile(join(siteRoot, 'dist/index.html'), 'utf8');
  if (/<(?:script|link)[^>]*(?:src|href)=["'](?:https?:)?\/\//i.test(html)) throw new Error('External bootstrap dependency');
  const catalog = JSON.parse(await readFile(join(clientRoot, 'app/catalog.json'), 'utf8'));
  const allFiles = [];
  const walk = async directory => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.isDirectory()) await walk(join(directory, entry.name));
      else allFiles.push(join(directory, entry.name));
    }
  };
  await walk(join(siteRoot, 'dist'));
  const records = Array.isArray(catalog) ? catalog : catalog.pokemon;
  for (const record of records) await lstat(join(siteRoot, 'dist/pokemon', `${record.id}.webp`));
  for (const asset of ['forest.webp', 'favicon.svg', 'habitats/water.webp', 'habitats/mountain.webp', 'habitats/grassland.webp', 'habitats/cave.webp', 'habitats/urban.webp']) await lstat(join(siteRoot, 'dist', asset));
  for (const file of allFiles.filter(file => /\.(css|js)$/.test(file))) {
    const content = await readFile(file, 'utf8');
    if (/(?:fetch\(|url\(\s*["']?|@import\s+["'])(?:https?:)?\/\//i.test(content)) throw new Error(`External runtime dependency in ${file}`);
  }
  console.log(`PokéHabitat: ${records.length} Pokémon, complete local assets, same-origin game API.`);
} finally {
  if (linked) await unlink(temporaryLink);
}
