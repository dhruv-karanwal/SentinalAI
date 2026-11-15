import assert from 'node:assert/strict';
import { test } from 'node:test';

import { isTerminal, nodeLabel, pollDelay, realId, scenarioKind, statusLine, summarizeStep } from './investigation.ts';

test('poll cadence backs off and only running is non-terminal', () => {
  assert.equal(pollDelay(0), 1000);
  assert.equal(pollDelay(15_000), 2000);
  assert.equal(pollDelay(120_000), 5000);
  assert.equal(isTerminal('running'), false);
  for (const s of ['completed', 'failed', 'interrupted']) assert.equal(isTerminal(s), true);
});

test('a graph worker step: tools counted once per name, ended with a note', () => {
  const s = summarizeStep({
    node: 'log_analysis',
    events: [
      { type: 'reply', text: '{}', action: 'call_tool', tool: 'list_alerts' },
      { type: 'tool_result', text: '{}', tool: 'list_alerts' },
      { type: 'reply', text: '{}', action: 'call_tool', tool: 'list_alerts' },
      { type: 'reply', text: '{}', action: 'note' },
    ],
  });
  assert.deepEqual(s, { node: 'log_analysis', label: 'Log analysis', toolCalls: 2, tools: ['list_alerts'],
    ended: 'note', routedTo: null });
});

test('a supervisor step records where it routed; unknown nodes keep their name', () => {
  const s = summarizeStep({ node: 'supervisor', events: [{ type: 'reply', text: '{}', action: 'route', agent: 'correlation' }] });
  assert.equal(s.ended, 'route');
  assert.equal(s.routedTo, 'correlation');
  assert.equal(nodeLabel('something_new'), 'something_new');
});

test('status lines say what happened in words', () => {
  const base = { started_utc: '2026-11-15T10:00:00Z', completed_utc: null, error: null };
  assert.match(statusLine({ ...base, status: 'running' }, Date.parse('2026-11-15T10:00:07Z')), /^Running for 7 s/);
  assert.equal(statusLine({ ...base, status: 'completed', completed_utc: '2026-11-15T10:00:42Z' }, 0), 'Completed in 42 s.');
  assert.match(statusLine({ ...base, status: 'failed', error: 'unparseable reply' }, 0), /^Failed: unparseable reply\./);
  assert.match(statusLine({ ...base, status: 'interrupted' }, 0), /^Interrupted/);
});

test('opaque ids map back only when known', () => {
  assert.equal(realId({ 'al-1': 'real-1' }, 'al-1'), 'real-1');
  assert.equal(realId({}, 'al-x'), null);
});

test('data-source labels never call a synthetic sample a dev scenario', () => {
  assert.equal(scenarioKind('russellmitchell'), 'dev scenario');
  assert.equal(scenarioKind('synthetic'), 'synthetic sample, not real telemetry');
  assert.equal(scenarioKind('fox'), 'replayed scenario');
  assert.equal(scenarioKind(null), 'no data source');
});
