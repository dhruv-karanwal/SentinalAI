import assert from 'node:assert/strict';
import { test } from 'node:test';

import { GLOSSARY } from '../content/glossary.ts';
import { SCREEN_GUIDE, TOUR } from '../content/about.ts';
import { collapseRuns, distinctLabels, glossaryAnswer, incidentLabel, mainFromNodes, searchGlossary, whatHappened } from './explain.ts';
import { placeLabels } from './graph.ts';

test('glossary has about 30 unique terms with short definitions', () => {
  assert.ok(GLOSSARY.length >= 30 && GLOSSARY.length <= 45, `${GLOSSARY.length} terms`);
  const ids = new Set(GLOSSARY.map((t) => t.id));
  assert.equal(ids.size, GLOSSARY.length);
  for (const t of GLOSSARY) {
    const sentences = t.definition.split(/(?<=[.!?])\s+(?=[A-Z0-9"])/).filter(Boolean);
    assert.ok(sentences.length <= 2, `${t.id}: ${sentences.length} sentences`);
    assert.ok(t.why.length > 10, t.id);
  }
  for (const need of ['alert', 'incident', 'wazuh', 'suricata', 'aminer', 'sigma', 'ioc', 'verifier', 'held-out', 'four-eyes', 'triage-rule', 'noise', 'oracle', 'shuffled', 'dataset-replay', 'coverage', 'citation', 'unsupported-claim', 'entity', 'evidence'])
    assert.ok(ids.has(need), need);
});

test('glossary search ranks exact terms and aliases first', () => {
  assert.equal(searchGlossary('What is Wazuh?')[0]?.id, 'wazuh');
  assert.equal(searchGlossary('what does H2 mean')[0]?.id, 'triage-rule');
  assert.equal(searchGlossary('IOC not measured')[0]?.id, 'ioc');
  assert.equal(searchGlossary('held-out scenario')[0]?.id, 'held-out');
  assert.deepEqual(searchGlossary('zzzz qqqq'), []);
  assert.ok(searchGlossary('the a of').length === 0, 'stop words alone match nothing');
});

test('offline glossary answer quotes the glossary or says it does not know', () => {
  const a = glossaryAnswer('what is a verifier');
  assert.ok(a.found && a.text.includes('Evidence verifier'));
  const b = glossaryAnswer('what is the capital of France');
  assert.equal(b.found, false);
  assert.match(b.text, /not in the glossary/);
});

const inc = {
  incident_id: 'inc-abc',
  severity: 'High',
  first_ts: '2022-01-24T03:01:07+00:00',
  last_ts: '2022-01-24T03:04:49+00:00',
  alert_ids: Array.from({ length: 3 }, (_, i) => `a${i}`),
  detail: {
    detectors: { wazuh: 2, aminer: 1 },
    entities: ['host:10.143.2.4', 'ip:192.168.230.122'],
    timeline: [
      { alert_id: 'a0', detector: 'wazuh', level: 'medium', rule_id: '31101', rule_name: 'Web 400 error', ts: '2022-01-24T03:01:07+00:00' },
      { alert_id: 'a1', detector: 'wazuh', level: 'medium', rule_id: '31101', rule_name: 'Web 400 error', ts: '2022-01-24T03:02:07+00:00' },
      { alert_id: 'a2', detector: 'aminer', level: 'none', rule_id: null, rule_name: 'New path', ts: '2022-01-24T03:04:49+00:00' },
    ],
  },
};

test('what happened is built from the incident data only', () => {
  const s = whatHappened(inc, { row: 'H3', severity: 'High', rule: 'a high-level alert, and ATT&CK-mapped or >= 2 detectors agree' });
  const many = { ...inc, detail: { ...inc.detail, entities: ['host:a', 'host:b', 'ip:1.1.1.1', 'ip:2.2.2.2'] } };
  assert.match(whatHappened(many, null), /concerned 2 hosts, from 2 source IPs\./);
  assert.match(whatHappened(many, null, { host: 'b', ip: '2.2.2.2' }), /concerned mostly host b \(2 hosts in all\), mostly from source IP 2\.2\.2\.2 \(2 source IPs in all\)\./);
  assert.deepEqual(mainFromNodes([{ kind: 'host', value: 'x', alerts: 2 }, { kind: 'host', value: 'y', alerts: 9 }, { kind: 'ip', value: 'z', alerts: 1 }]), { host: 'y', ip: 'z' });
  assert.match(s, /^Between 2022-01-24 03:01:07 and 03:04:49 UTC \(data time, 3 min 42 s\), 3 alerts from Wazuh and AMiner/);
  assert.match(s, /host 10\.143\.2\.4/);
  assert.match(s, /source IP 192\.168\.230\.122/);
  assert.match(s, /most frequent rule was "Web 400 error" \(2 of 3 alerts\)/);
  assert.match(s, /Triage rated it High because a high-level alert, and ATT&CK-mapped or >= 2 detectors agree \(rule H3\)\.$/);
  const bare = whatHappened({ ...inc, detail: {} }, null);
  assert.match(bare, /3 alerts/);
  assert.doesNotMatch(bare, /undefined|null|NaN/);
});

test('incident label names the main entity and the data time', () => {
  assert.equal(incidentLabel(inc), 'host 10.143.2.4 · 2022-01-24 03:01 UTC');
  assert.equal(incidentLabel({ ...inc, detail: { entities: ['ip:1.2.3.4'] } }), 'IP 1.2.3.4 · 2022-01-24 03:01 UTC');
  assert.equal(incidentLabel({ ...inc, detail: {} }), 'inc-abc · 2022-01-24 03:01 UTC');
  assert.equal(incidentLabel({ ...inc, detail: { entities: ['host:a', 'host:b'], main_host: 'b' } }), 'host b · 2022-01-24 03:01 UTC');
  assert.equal(incidentLabel({ ...inc, detail: { entities: ['host:a', 'host:b'] } }), 'inc-abc · 2022-01-24 03:01 UTC');
});

test('collapseRuns merges consecutive identical rows and keeps counts', () => {
  const r = (id: string, rule: string, host: string) => ({ alert_id: id, detector: 'wazuh', rule_id: rule, rule_name: rule, severity: 3, host_ip: host, src_ip: null, ts: id });
  const runs = collapseRuns([r('1', 'x', 'h'), r('2', 'x', 'h'), r('3', 'y', 'h'), r('4', 'x', 'h')]);
  assert.deepEqual(runs.map((g) => [g.first.alert_id, g.count]), [['1', 2], ['3', 1], ['4', 1]]);
  assert.deepEqual(collapseRuns([]), []);
});

test('placeLabels never overlaps and is deterministic', () => {
  const nodes = [
    { id: 'big', x: 50, y: 50, r: 8, text: '10.0.0.1' },
    { id: 'near', x: 52, y: 52, r: 3, text: '10.0.0.2' },
    { id: 'far', x: 300, y: 200, r: 3, text: '10.0.0.3' },
  ];
  const out = placeLabels(nodes, 400, 300, 6, 12);
  const ids = out.map((b) => b.id);
  assert.ok(ids.includes('big') && ids.includes('far'));
  for (let i = 0; i < out.length; i++)
    for (let j = i + 1; j < out.length; j++) {
      const a = out[i]!;
      const b = out[j]!;
      assert.ok(a.x1 <= b.x0 || b.x1 <= a.x0 || a.y1 <= b.y0 || b.y1 <= a.y0);
    }
  assert.deepEqual(placeLabels(nodes, 400, 300, 6, 12), out);
  assert.deepEqual(placeLabels([], 10, 10, 6, 12), []);
});

test('tour has six stops in the agreed order and every screen guide names a route', () => {
  assert.deepEqual(TOUR.map((s) => s.path), ['/about', '/overview', '/incidents', '/alerts', '/approvals', '/study']);
  for (const g of SCREEN_GUIDE) assert.match(g.path, /^\/[a-z]+$/);
});

test('distinctLabels makes repeated labels unique', () => {
  const a = { incident_id: 'inc-1', first_ts: '2022-01-24T03:01:07Z', detail: { entities: ['host:h'] } };
  const b = { incident_id: 'inc-2', first_ts: '2022-01-24T03:01:50Z', detail: { entities: ['host:h'] } };
  const c = { incident_id: 'inc-3', first_ts: '2022-01-25T03:01:07Z', detail: { entities: ['host:h'] } };
  const m = distinctLabels([a, b, c]);
  assert.equal(new Set(m.values()).size, 3);
  assert.equal(m.get('inc-3'), 'host h · 2022-01-25 03:01 UTC');
  assert.match(m.get('inc-1')!, /inc-1$/);
});
