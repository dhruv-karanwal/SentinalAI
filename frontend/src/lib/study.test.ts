import assert from 'node:assert/strict';
import { test } from 'node:test';

import { latestRevision, revisionKey } from './study.ts';

test('revision order is numeric per part, unknown first (same rule as backend app/study/revisions.py)', () => {
  assert.ok(revisionKey('m5-v10+wave-c-v2') > revisionKey('m5-v9+wave-c-v2'));
  assert.ok(revisionKey('m5-v3+wave-c-v2') > revisionKey('m5-v2+wave-c-v1'));
  assert.ok(revisionKey('unknown') < revisionKey('m5-v1+wave-c-v1'));
});

test('latestRevision picks the newest present, null when there are none', () => {
  assert.equal(latestRevision(['m5-v2+wave-c-v1', 'm5-v3+wave-c-v2', 'm5-v2+wave-c-v1']), 'm5-v3+wave-c-v2');
  assert.equal(latestRevision(['unknown']), 'unknown');
  assert.equal(latestRevision([]), null);
});
