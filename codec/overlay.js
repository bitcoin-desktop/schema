// Schema overlays: a chain, a structure or a rule that is not part of the
// Bitcoin model arrives as another JSON-LD graph and is merged in *additively*.
// An overlay may only add nodes; redefining an `@id` that already exists is an
// error, so the base model cannot be edited by an overlay, only extended.
// A node may `extends` an earlier node: missing keys are copied from it, so a
// forked chain declares just what differs from the chain it forked.
//
// An overlay is one graph spanning modules (chains, structs, rules), while the
// base model is several documents, so a merge into one document leaves
// references it cannot see (an `extends` or `ruleSet` that lives in another
// document) untouched for the merge that can. Only a reference that resolves
// to the wrong kind of node is an error here; a chain that never resolved its
// `extends` is refused by createKernel.
export function mergeSchemas(base, ...overlays) {
  const graph = [];
  const byId = new Map();
  const add = (node, origin) => {
    const id = node['@id'];
    if (id && byId.has(id)) throw new Error(`overlay ${origin} redefines ${id}`);
    const parent = node.extends ? byId.get(node.extends) : null;
    if (parent) {
      const { extends: _, ...own } = node;
      node = { ...parent, ...own, '@id': id };
    }
    if (id) byId.set(id, node);
    graph.push(node);
  };
  for (const node of base['@graph'] ?? []) add(node, 'base');
  overlays.forEach((o, i) => { for (const node of o['@graph'] ?? []) add(node, o['@id'] ?? `#${i + 1}`); });
  // A ValidationRule node with `ruleSet` joins that set (appended, in overlay
  // order). The set node is cloned first so the base graph is never mutated.
  for (const node of graph.slice()) {
    if (node['@type'] !== 'ValidationRule' || !node.ruleSet) continue;
    const set = byId.get(node.ruleSet);
    if (!set) continue; // lives in another document
    if (set['@type'] !== 'RuleSet') throw new Error(`${node['@id']}: ruleSet ${node.ruleSet} is not a RuleSet`);
    if (!set.__overlayClone) {
      const clone = { ...set, rules: [...(set.rules ?? [])] };
      Object.defineProperty(clone, '__overlayClone', { value: true, enumerable: false });
      graph[graph.indexOf(set)] = clone; byId.set(set['@id'], clone);
    }
    byId.get(node.ruleSet).rules.push(node);
  }
  const context = Object.assign({}, base['@context'], ...overlays.map((o) => o['@context'] ?? {}));
  return { ...base, '@context': context, '@graph': graph };
}
