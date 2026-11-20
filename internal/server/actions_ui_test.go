package server

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestActionsUIQueriesEachSection(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node unavailable")
	}
	path, err := filepath.Abs("../../web/static/actions.js")
	if err != nil {
		t.Fatal(err)
	}
	// Run the real view against a minimal DOM/API. History changes must fetch
	// another bounded server section; counts must use the settings statistics.
	script := `
const assert = require('node:assert/strict');
const fs = require('node:fs');
const source = fs.readFileSync(process.argv[1], 'utf8').replace(/^import .*;\r?$/gm, '');
const elements = [], requests = [];
function el(tag, attrs = {}, ...children) {
  const n = { tag, attrs, children: children.flat(Infinity), value: attrs.value || '', listeners: {},
    append(...c) { this.children.push(...c.flat(Infinity)); },
    replaceChildren(...c) { this.children = c.flat(Infinity); },
    addEventListener(type, callback) { this.listeners[type] = callback; }
  };
  if (tag === 'select') n.value = n.children[0].value;
  elements.push(n);
  return n;
}
const sample = state => ({ id: 1, state, device_id: 1, decided_by: [], reason: '', action: '' });
async function api(path) {
  requests.push(path);
  if (path === '/api/decide/settings') return { killswitch: false, rules: [], guards: [], stats: { pending: 900, auto: 800, notify: 700 } };
  const u = new URL(path, 'http://test');
  assert.equal(u.pathname, '/api/proposals');
  assert.equal(u.searchParams.get('limit'), '500');
  const states = u.searchParams.get('state');
  assert.ok(states, 'every section needs a server state filter');
  return [sample(states.split(',')[0])];
}
let page;
const registerView = (id, title, view) => { page = view; };
new Function('api', 'el', 'table', 'fmtTime', 'registerView', 'ago', 'vulnCell', source)(api, el, (cols, rows) => ({rows}), x => x, registerView, x => x, x => x);
(async () => {
  const root = el('main');
  await page(root);
  assert.ok(requests.includes('/api/proposals?state=pending&limit=500'));
  assert.ok(requests.includes('/api/proposals?state=auto&limit=500'));
  assert.ok(requests.includes('/api/proposals?state=approved,rejected,expired,resolved,notify&limit=500'));
  assert.equal(root.children[2].children[1].rows[0].state, 'pending');
  assert.equal(root.children[3].children[1].rows[0].state, 'auto');
  const strings = n => typeof n === 'string' ? n : (n?.children || []).map(strings).join(' ');
  assert.match(strings(root.children[0]), /pending: 900/);
  assert.match(strings(root.children[0]), /auto: 800/);
  const select = elements.find(n => n.tag === 'select');
  select.value = 'approved';
  await select.listeners.change();
  assert.equal(requests.at(-1), '/api/proposals?state=approved&limit=500');
})().catch(e => { console.error(e); process.exitCode = 1; });
`
	if out, err := exec.Command(node, "-e", script, path).CombinedOutput(); err != nil {
		t.Fatalf("Actions UI: %v\n%s", err, out)
	}
}
