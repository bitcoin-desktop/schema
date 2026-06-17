#!/usr/bin/env node
// Generate the core data-model class diagram FROM the schema, so it can
// never drift. Emits Mermaid (for the README, which GitHub renders inline)
// and a zero-dependency SVG (for the site). Curated to the core consensus
// structs; field content is schema-derived, layout is hand-placed.
//
//   node tools/gen-class-diagram.js
//     -> writes docs/class-diagram.mmd and class-diagram.svg
//     -> prints the Mermaid block to stdout for the README

import { readFile, writeFile, mkdir } from 'node:fs/promises';

const root = new URL('..', import.meta.url);
const core = JSON.parse(await readFile(new URL('schema/core.jsonld', root), 'utf8'));
const structs = new Map(
  core['@graph'].filter((n) => n['@type'] === 'ConsensusStruct').map((n) => [n['@id'], n]));
const short = (id) => id.replace('btc:', '');
const isStruct = (id) => typeof id === 'string' && structs.has(id);

// model: per struct, literal attributes, derived (UML /derived), and refs
function model(node) {
  const attrs = [], refs = [];
  for (const f of node.fields ?? []) {
    if (isStruct(f.structType)) refs.push({ to: f.structType, mult: '1', label: f.label });
    else if (isStruct(f.itemType)) refs.push({ to: f.itemType, mult: f.presentIf ? '0..*' : '1..*', label: f.label });
    else attrs.push({ name: f.label, type: f.itemType ? `${short(f.itemType ?? '')}[]` || 'vec' : f.wireType, opt: !!f.presentIf });
  }
  const derived = (node.derived ?? []).map((d) => d.label);
  return { id: node['@id'], label: node.label, attrs, derived, refs };
}
const models = [...structs.values()].map(model);

// ---- Mermaid ----
function mermaid() {
  const L = ['classDiagram', '  direction TB'];
  for (const m of models) {
    L.push(`  class ${m.label} {`);
    for (const a of m.attrs) L.push(`    +${a.type}${a.opt ? '?' : ''} ${a.name}`);
    for (const d of m.derived) L.push(`    +${d}() derived`); // computed, not stored
    L.push('  }');
  }
  for (const m of models) for (const r of m.refs) {
    L.push(`  ${m.label} "1" *-- "${r.mult}" ${short(r.to)} : ${r.label}`);
  }
  return L.join('\n');
}

// ---- SVG (curated layout; box content schema-derived). Styles are inlined
// as presentation attributes so the file renders identically in browsers and
// in basic SVG rasterizers (no <style> stylesheet dependency). ----
const POS = {
  'btc:Block':             { x: 490, y: 20 },
  'btc:BlockHeader':       { x: 110, y: 200 },
  'btc:Transaction':       { x: 640, y: 200 },
  'btc:TransactionInput':  { x: 450, y: 480 },
  'btc:TransactionOutput': { x: 700, y: 480 },
  'btc:Witness':           { x: 950, y: 480 },
  'btc:OutPoint':          { x: 450, y: 700 },
};
const W = 230, HEAD = 34, LINE = 24, PAD = 10;
const MONO = 'ui-monospace, Menlo, Consolas, monospace';
const SANS = 'system-ui, sans-serif';
const C = { bg: '#ffffff', panel: '#f6f8fa', border: '#d0d7de', fg: '#1f2328',
  muted: '#57606a', accent: '#e8830c', link: '#0969da', edge: '#9aa3ad' };

function rowCount(m) { return m.attrs.length + (m.derived.length ? 1 : 0); }
function boxH(m) { return HEAD + PAD + rowCount(m) * LINE + PAD; }
function esc(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;'); }

function svg() {
  const box = new Map(models.map((m) => [m.id, { m, ...POS[m.id], h: boxH(m) }]));
  const edges = [], boxes = [];
  for (const { m, x, y, h } of box.values()) {
    let yy = y + HEAD + PAD + 16;
    const CHW = 8.1; // monospace advance at 13.5px — lets us place the type without tspan flow
    const rows = m.attrs.map((a) => {
      const tx = x + 14 + (a.name.length + 1) * CHW;
      const t = `<text x="${x + 14}" y="${yy}" font-family="${MONO}" font-size="13.5" fill="${C.fg}">${esc(a.name)}</text>`
        + `<text x="${tx}" y="${yy}" font-family="${MONO}" font-size="13.5" fill="${C.accent}">: ${esc(a.type)}${a.opt ? '?' : ''}</text>`;
      yy += LINE; return t;
    });
    if (m.derived.length) rows.push(
      `<text x="${x + 14}" y="${yy}" font-family="${MONO}" font-size="12.5" font-style="italic" fill="${C.link}">/${m.derived.join(' /')}</text>`);
    boxes.push(`<g>
    <rect x="${x}" y="${y}" width="${W}" height="${h}" rx="10" fill="${C.panel}" stroke="${C.border}" stroke-width="1"/>
    <line x1="${x}" y1="${y + HEAD}" x2="${x + W}" y2="${y + HEAD}" stroke="${C.border}"/>
    <text x="${x + W / 2}" y="${y + 23}" font-family="${SANS}" font-weight="700" font-size="16" fill="${C.fg}" text-anchor="middle">${esc(m.label)}</text>
    ${rows.join('\n    ')}
  </g>`);
  }
  // composition edges: filled diamond at the WHOLE (parent) side, orthogonal routing
  for (const { m, x, y, h } of box.values()) {
    for (const r of m.refs) {
      const t = box.get(r.to); if (!t) continue;
      const px = x + W / 2, py = y + h;
      const cx = t.x + W / 2, cy = t.y;
      const midY = py + (cy - py) / 2;
      edges.push(`<path d="M${px},${py + 9} L${px},${midY} L${cx},${midY} L${cx},${cy}" fill="none" stroke="${C.edge}" stroke-width="1.4"/>
    <path d="M${px},${py} l8,9 l-8,9 l-8,-9 z" fill="${C.fg}"/>
    <text x="${px + 12}" y="${py + 16}" font-family="${MONO}" font-size="11" fill="${C.muted}">1</text>
    <text x="${cx + 8}" y="${cy - 6}" font-family="${MONO}" font-size="11" fill="${C.muted}">${r.mult}</text>
    <text x="${cx}" y="${midY - 6}" font-family="${MONO}" font-size="12" fill="${C.muted}" text-anchor="middle">${esc(r.label)}</text>`);
    }
  }
  const H = Math.max(...[...box.values()].map((b) => b.y + b.h)) + 56;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="${H}" viewBox="0 0 1200 ${H}">
  <rect width="1200" height="${H}" fill="${C.bg}"/>
  <rect width="1200" height="8" fill="${C.accent}"/>
  ${edges.join('\n  ')}
  ${boxes.join('\n  ')}
  <text x="1184" y="${H - 16}" text-anchor="end" font-family="${MONO}" font-size="12.5" fill="${C.muted}">generated from schema/core.jsonld  ·  ◆ composition  ·  /name = derived (computed, not stored)</text>
</svg>`;
}

const mmd = mermaid();
await mkdir(new URL('docs/', root), { recursive: true });
await writeFile(new URL('docs/class-diagram.mmd', root), mmd + '\n');
await writeFile(new URL('class-diagram.svg', root), svg() + '\n');
console.log('```mermaid\n' + mmd + '\n```');
