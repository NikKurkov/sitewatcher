const assert = require('node:assert/strict');
class Element {
  get childNodes() { return this.children; }
  constructor() { this.dataset = {}; this.children = []; this.classList = {add(){}, toggle(){}}; this.style = {}; this.textContent = ''; }
  setAttribute(key, value) { this[key] = value; }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = items; }
  before() {}
  querySelector(selector) { return this.elements?.[selector] || null; }
  addEventListener() {}
  getBoundingClientRect() { return {width: 1200}; }
}
global.document = {createElementNS: () => new Element(), createElement: () => new Element(),
  documentElement: {lang: 'en'}, querySelector: () => ({value: 'fake-csrf'})};
global.window = {};
require(process.cwd() + '/sitewatcher/webapp/static/sitewatcher/route_view.js');
const svg = new Element();
svg.elements = {'[data-scene-nodes]': new Element()};
const controls = new Element();
Object.assign(controls.dataset, {hostnameUnavailable:'Hostname unavailable', noResponse:'No response', hop:'Hop', ms:'ms'});
controls.elements = Object.fromEntries(['refresh','disable','toggle','follow','domain','state','details','list','captured'].map(key => [`[data-route-${key}]`, new Element()]));
const panel = new Element();
panel.elements = {'[data-route-controls]': controls, '[data-activity-scene]': svg};
let changes = 0;
const view = new window.SiteWatcherRouteView(panel, () => changes++);
assert.equal(changes, 0);
const result = {method: 'udp', destination_ip: '203.0.113.2', reached: true,
  captured_at: '2026-11-04T12:00:00Z', hops: [{ttl:1,ip:null,hostname:null,rtt_ms:null},
    {ttl:2,ip:'203.0.113.2',hostname:'example.test',rtt_ms:2}]};
view.update([{name:'example.test', route:{enabled:true,state:'ready',result}}], 'example.test');
assert.equal(view.active, false);
view.desired = true;
view.select('example.test');
assert.equal(view.active, true);
assert.equal(changes, 1);
assert.equal(view.geometry.points.length, 3);
assert.equal(view.geometry.points[0].x, view.geometry.hub.x + 95 * view.geometry.hub.scale);
assert.equal(view.geometry.points.at(-1).x, view.geometry.target.x - 20);
assert.equal(view.paddles.length, 1);
view.showHop(0);
assert.equal(view.detailNodes.hostname.textContent, 'Hostname unavailable');
assert.equal(view.detailNodes.rtt.textContent, 'No response');
view.showHop(1);
assert.equal(view.detailNodes.ip.textContent, '203.0.113.2');
assert.equal(view.detailNodes.hostname.textContent, 'example.test');
assert.match(view.detailNodes.rtt.textContent, /^2\.0 /);
assert.equal(view.geometry.width, 1200);
view.pinnedHop = 1;
view.resize(320);
assert.equal(view.pinnedHop, 1);
assert.equal(view.geometry.width, 620);
assert.equal(view.geometry.compact, true);
view.resize(1200);
assert.equal(controls.elements['[data-route-list]'].children.length, 2);
view.update([{name:'example.test',route:{enabled:true,state:'ready',result}}], 'example.test');
assert.equal(changes, 3);
view.step([{event:{domain:'example.test'},phase:'out',progress:.5}]);
view.select(null);
assert.equal(view.active, false);
assert.equal(view.geometry, null);
assert.equal(changes, 4);
view.select('example.test');
assert.equal(view.active, true);
panel.dataset.routeReadOnly = 'true';
let requests = 0;
global.fetch = async () => { requests++; return {ok:true,json:async()=>({saved:true})}; };
(async () => {
 await view.save('refresh');
 assert.equal(requests, 0);
 panel.dataset.routeReadOnly = 'false';
 await view.save('refresh');
 assert.equal(requests, 1);
 assert.equal(view.route().state, 'queued');
 view.reset();
 assert.equal(view.detail.hidden, true);
 assert.equal(view.active, false);
 assert.equal(view.geometry, null);
 assert.equal(view.selectedName, null);
 assert.equal(view.domains.size, 0);
 view.update([{name:'example.test',route:{enabled:true,state:'ready',result}}], 'example.test');
 let release;
 global.fetch = () => new Promise(resolve => { release = resolve; });
 const pending = view.save('refresh');
 assert.equal(view.busy, true);
 view.reset();
 assert.equal(view.busy, false);
 release({ok:true,json:async()=>({saved:true})});
 await pending;
 assert.equal(view.active, false);
 assert.equal(view.desired, false);
 assert.equal(view.selectedName, null);
 assert.equal(view.domains.size, 0);
 assert.equal(view.message, '');
 const dense = {...result, reached:false, hops:Array.from({length:24}, (_,i)=>({ttl:i+1,ip:'192.0.2.'+(i+1),hostname:null,rtt_ms:1}))};
 view.update([{name:'example.test',route:{enabled:true,state:'partial',result:dense}}], 'example.test');
 view.desired = true; view.select('example.test');
 for (const width of [1200,320]) {
  view.resize(width);
  assert.equal(view.paddles.length,24);
  assert.ok(view.geometry.points.every(p=>p.x>=0 && p.x<=view.geometry.width && p.y>=0 && p.y<=view.geometry.height));
 }
 console.log('Route helper behavior and late-save reset checks passed');
})();
