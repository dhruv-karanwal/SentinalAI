import assert from 'node:assert/strict';
import { test } from 'node:test';

import { filterRank, groupNav, matchScore, NAV, NAV_GROUPS, railMove } from './nav.ts';

test('every visible screen is in exactly one rail group, hidden ones in none', () => {
  const grouped = NAV_GROUPS.flatMap((g) => g.paths);
  assert.equal(new Set(grouped).size, grouped.length);
  for (const n of NAV) assert.equal(grouped.includes(n.path), !n.hidden, n.path);
  assert.deepEqual(NAV_GROUPS.map((g) => g.label), ['Understand', 'Monitor', 'Investigate', 'Respond', 'Govern']);
});

test('groupNav drops items the role lacks and empty groups', () => {
  const noStudyNoGovern = NAV.filter((n) => !['/study', '/audit', '/users', '/settings'].includes(n.path));
  const groups = groupNav(noStudyNoGovern);
  assert.deepEqual(groups.map((g) => g.label), ['Understand', 'Monitor', 'Investigate', 'Respond']);
  assert.deepEqual(groups[0]!.items.map((i) => i.path), ['/about']);
  assert.ok(!groups.some((g) => g.items.some((i) => i.hidden)));
});

test('railMove wraps and handles Home / End', () => {
  assert.equal(railMove(3, 0, 'ArrowDown'), 1);
  assert.equal(railMove(3, 2, 'ArrowDown'), 0);
  assert.equal(railMove(3, 0, 'ArrowUp'), 2);
  assert.equal(railMove(3, -1, 'ArrowDown'), 0);
  assert.equal(railMove(3, 1, 'End'), 2);
  assert.equal(railMove(3, 1, 'Home'), 0);
  assert.equal(railMove(3, 1, 'x'), null);
  assert.equal(railMove(0, 0, 'ArrowDown'), null);
});

test('matchScore ranks exact > prefix > word prefix > substring > in-order letters', () => {
  assert.equal(matchScore('Alerts', 'alerts'), 4);
  assert.equal(matchScore('Alerts', 'al'), 3);
  assert.equal(matchScore('Toggle theme', 'the'), 2);
  assert.equal(matchScore('Approvals', 'rov'), 1);
  assert.equal(matchScore('Incidents', 'icd'), 0.5);
  assert.equal(matchScore('Incidents', 'zz'), 0);
  assert.equal(matchScore('Anything', '  '), 1);
});

test('filterRank keeps all on an empty query, filters and orders otherwise (stable ties)', () => {
  const items = [{ label: 'Audit' }, { label: 'Alerts' }, { label: 'Approvals' }, { label: 'Toggle theme', keywords: 'dark light' }];
  assert.equal(filterRank(items, '').length, 4);
  assert.deepEqual(filterRank(items, 'a').map((i) => i.label), ['Audit', 'Alerts', 'Approvals', 'Toggle theme']);
  assert.deepEqual(filterRank(items, 'al').map((i) => i.label), ['Alerts', 'Approvals']);
  assert.deepEqual(filterRank(items, 'dark').map((i) => i.label), ['Toggle theme']);
  assert.deepEqual(filterRank(items, '10.143.2.4'), []);
});
