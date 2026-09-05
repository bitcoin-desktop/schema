// One entry point that wires the schema-driven engines for a network, with
// optional overlays (see overlay.js): each overlay is { graph, install }, where
// `graph` is its JSON-LD and `install(codec, engines)` registers the code it
// needs (proof-of-work hash, derived fields, rule checks). With no overlays this
// is exactly the hand wiring the tests and apps have always done.
import { Codec } from './codec.js';
import { ScriptEngine } from './script.js';
import { ScriptInterpreter } from './interpreter.js';
import { HeaderEngine } from './headers.js';
import { BlockEngine } from './blocks.js';
import { mergeSchemas } from './overlay.js';

export function createKernel({ core, proof, script, chain, validate, network = 'btc:mainnet', overlays = [] }) {
  const graphs = overlays.map((o) => o.graph);
  const chainG = mergeSchemas(chain, ...graphs);
  const validateG = mergeSchemas(validate, ...graphs);
  const net = chainG['@graph'].find((n) => n['@id'] === network);
  if (!net) throw new Error(`unknown network: ${network}`);
  if (net.extends) throw new Error(`${network} extends unknown ${net.extends}`);
  const codec = new Codec(core, proof, ...graphs);
  for (const o of overlays) o.install?.(codec); // PoW hashes, derived fields — before the chain is bound
  const headers = HeaderEngine.fromSchemas(codec, chainG, validateG, network);
  const scriptEngine = script ? ScriptEngine.fromSchemas(script, chainG, network) : null;
  const limits = script?.['@graph'].find((n) => n['@id'] === 'btc:scriptLimits');
  const interpreter = scriptEngine ? new ScriptInterpreter(codec, scriptEngine, limits) : null;
  const blocks = BlockEngine.fromSchemas(codec, chainG, validateG, script, network);
  const engines = { codec, headers, blocks, script: scriptEngine, interpreter, network, params: headers.params, schemas: { chain: chainG, validate: validateG } };
  for (const o of overlays) o.installChecks?.(engines);
  return engines;
}
