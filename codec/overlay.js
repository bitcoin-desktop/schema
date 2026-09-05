// Schema overlays: a chain, a structure or a rule that is not part of the
// Bitcoin model arrives as another JSON-LD graph and is merged in *additively*.
// An overlay may only add nodes; redefining an `@id` that already exists is an
// error, so the base model cannot be edited by an overlay, only extended.
// A node may `extends` an earlier node: missing keys are copied from it, so a
// forked chain declares just what differs from the chain it forked.
export function mergeSchemas(base, ...overlays) {
  const graph = [];
  const byId = new Map();
  const add = (node, origin) => {
    const id = node['@id'];
    if (id && byId.has(id)) throw new Error(`overlay ${origin} redefines ${id}`);
    if (node.extends) {
      const parent = byId.get(node.extends);
      if (!parent) throw new Error(`${id} extends unknown ${node.extends}`);
      const { extends: _, ...own } = node;
      node = { ...parent, ...own, '@id': id };
    }
    if (id) byId.set(id, node);
    graph.push(node);
  };
  for (const node of base['@graph'] ?? []) add(node, 'base');
  overlays.forEach((o, i) => { for (const node of o['@graph'] ?? []) add(node, o['@id'] ?? `#${i + 1}`); });
  const context = Object.assign({}, base['@context'], ...overlays.map((o) => o['@context'] ?? {}));
  return { ...base, '@context': context, '@graph': graph };
}
