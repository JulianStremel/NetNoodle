package server

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIntegrationsUIWizard(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node unavailable")
	}
	path, err := filepath.Abs("../../web/static/integrations.js")
	if err != nil {
		t.Fatal(err)
	}
	script := `
const assert = require('node:assert/strict');
const fs = require('node:fs');
const source = fs.readFileSync(process.argv[1], 'utf8').replace(/^import .*;\r?$/gm, '');
assert.ok(!source.includes('innerHTML'));
function el(tag, attrs = {}, ...children) {
  const n = { tag, attrs, children: children.flat(Infinity).filter(x => x != null && x !== false),
    value: attrs.value ?? '', checked: false, disabled: Boolean(attrs.disabled), hidden: Boolean(attrs.hidden), listeners: {},
    append(...c) { this.children.push(...c.flat(Infinity).filter(x => x != null && x !== false)); },
    replaceChildren(...c) { this.children = c.flat(Infinity).filter(x => x != null && x !== false); },
    addEventListener(event, cb) { this.listeners[event] = cb; }, focus() {}, reportValidity() { return true; },
  };
  if (tag === 'select') n.value = n.children[0]?.attrs.value;
  return n;
}
const text = n => typeof n === 'string' ? n : (n?.children || []).map(text).join(' ');
const all = n => [n, ...(n.children || []).filter(c => typeof c === 'object').flatMap(all)];
const find = (n, pred) => { const found = all(n).find(pred); assert.ok(found, 'element exists'); return found; };
const click = async (n, label) => { const b = find(n, c => c.tag === 'button' && text(c) === label); await b.attrs.onclick(); return b; };
const submit = async n => n.listeners.submit({preventDefault(){}});
const input = (n, label) => find(n, c => c.attrs?.['aria-label'] === label);
const fields = [
  {key:'endpoint',label:'Endpoint',type:'url',required:true,default:'https://service'},
  {key:'pin',label:'Certificate',type:'fingerprint'},
  {key:'credential',label:'Credential',type:'secret',required:true},
  {key:'active',label:'Active',type:'bool',default:true},
  {key:'tags',label:'Tags',type:'list'},
  {key:'period',label:'Period',type:'duration',default:'10m'},
  {key:'extra',label:'Extra',type:'string',default:'anything'},
];
const schema = {type:'a-new-plugin-without-ui-code',fields};
let rows = [{id:1,type:schema.type,name:'saved',enabled:true,settings:{endpoint:'https://saved',active:false},secrets:{credential:{set:true}},running:true},
  {id:0,type:schema.type,name:'config',enabled:true,settings:{},secrets:{},from_config:true}];
const calls = [];
async function api(path, options) {
  calls.push({path,options});
  if (path === '/api/integrations/types') return [schema];
  if (!options) return rows;
  if (path === '/api/integrations/probe') return {fingerprint:'a'.repeat(64),subject:'<img src=x onerror=alert(1)>'};
  if (path === '/api/integrations/test') return {ok:true,entities:2,error:''};
  return {ok:true,id:2};
}
let page;
new Function('api','el','ago','registerView','setInterval','clearInterval','window', source)(api,el,x=>x||'never',
  (name,title,view) => {assert.equal(name,'integrations');page=view;}, () => 1, () => {}, {addEventListener(){}});
(async () => {
  const root = el('main'); await page(root);
  const editor = root.children[3], list = root.children[4];
  assert.equal(all(list.children[1]).filter(n => n.tag === 'button').length,0,'config is read only');
  assert.match(text(list.children[1]),/from config file/);
  await click(root,'Add integration'); await submit(editor.children[0]);
  let form = editor.children[0];
  let save = find(form,n=>n.tag==='button' && text(n)==='Save');
  assert.equal(save.disabled,true);
  assert.equal(input(form,'Active').checked,true);
  assert.equal(input(form,'Extra').value,'anything','new plugin fields come from schema');
  input(form,'Credential').value='write-only-key';
  input(form,'Tags').value='first\n second\n\n';
  await click(form,'Fetch fingerprint');
  assert.equal(input(form,'Certificate').value,'','fetch must not silently trust certificate');
  assert.ok(!all(form).some(n=>n.tag==='img'),'certificate subject stays text');
  const before = calls.filter(c=>c.path==='/api/integrations/test').length;
  await click(form,'Test connection');
  assert.equal(calls.filter(c=>c.path==='/api/integrations/test').length,before,'unconfirmed pin blocks test');
  await click(form,'I compared it — use this fingerprint');
  assert.equal(input(form,'Certificate').value,'a'.repeat(64));
  await click(form,'Test connection'); assert.equal(save.disabled,false);
  input(form,'Extra').value='changed'; input(form,'Extra').listeners.input(); assert.equal(save.disabled,true,'edit invalidates test');
  await click(form,'Test connection');
  const password = find(form,n=>n.tag==='input' && n.attrs.autocomplete==='current-password'); password.value='admin-password';
  await submit(form);
  let saved = calls.find(c=>c.path==='/api/integrations' && c.options?.method==='POST').options.body;
  assert.equal(saved.type,schema.type); assert.equal(saved.password,'admin-password');
  assert.deepEqual(saved.secrets,{credential:'write-only-key'}); assert.equal(saved.settings.credential,undefined);
  assert.deepEqual(saved.settings.tags,['first','second']); assert.equal(password.value,'');
  await click(list.children[0],'Edit'); form=editor.children[0];
  assert.equal(input(form,'Credential').value,''); assert.equal(input(form,'Credential').attrs.required,false);
  await click(form,'Test connection');
  assert.equal(calls.filter(c=>c.path==='/api/integrations/test').at(-1).options.body.id,1,'edit test can reuse saved secrets');
  find(form,n=>n.tag==='input' && n.attrs.autocomplete==='current-password').value='admin-password';
  await submit(form);
  saved=calls.find(c=>c.options?.method==='PUT').options.body;
  assert.deepEqual(saved.secrets,{credential:''},'blank preserves the stored credential'); assert.equal(saved.id,undefined);
  for (const action of ['disable','delete']) {
    await click(list.children[0],action[0].toUpperCase()+action.slice(1));
    form=editor.children[0]; find(form,n=>n.tag==='input').value='admin-password'; await submit(form);
    const request=calls.filter(c=>c.options && (c.path.endsWith('/disable') || c.options.method==='DELETE')).at(-1);
    assert.equal(request.options.body.password,'admin-password');
  }
})().catch(err=>{console.error(err);process.exitCode=1;});
`
	if out, err := exec.Command(node, "-e", script, path).CombinedOutput(); err != nil {
		t.Fatalf("Integrations UI: %v\n%s", err, out)
	}
}
