// Navigation model of the shell (DESIGN.md 5): the screens, their rail groups, and the pure
// filtering / ranking of the command palette. No React and no API here, so node:test covers it.

import type { Role } from '../api.ts';
import type { IconName } from '../icons.tsx';

export interface NavItem {
  path: string;
  label: string;
  icon: IconName;
  /** second key of the `g x` shortcut */
  key?: string;
  permission?: string;
  roles?: Role[];
  /** reachable by link only (not in the rail or the palette) */
  hidden?: boolean;
  about: string;
}

export const NAV: readonly NavItem[] = [
  { path: '/about', label: 'About', icon: 'about', key: 'h', about: 'How SentinelAI works: the problem, the pipeline, the study question, what each screen shows, limits and the glossary.' },
  { path: '/study', label: 'Study', icon: 'study', key: 's', permission: 'read.raw', about: 'Matched-budget pilot results rendered from the result files (dev scenarios, pilot numbers).' },
  { path: '/overview', label: 'Overview', icon: 'overview', key: 'o', about: 'Charts over the stored alerts and incidents; each chart filters the alert table under it.' },
  { path: '/executive', label: 'Executive', icon: 'executive', key: 'e', about: 'One printable page: severity trend, top risks, ATT&CK coverage, time to review, open approvals.' },
  { path: '/incidents', label: 'Incidents', icon: 'incidents', key: 'i', about: 'The triage queue: incident table, detail with the detector strip, ATT&CK lanes, entity graph, evidence and findings.' },
  { path: '/alerts', label: 'Alerts', icon: 'alerts', key: 'a', about: 'Every stored alert with facet counts, saved filters and CSV export.' },
  { path: '/ask', label: 'Ask', icon: 'ask', key: 'k', permission: 'copilot.ask', about: 'Questions to the copilot about an incident, with verified citations (needs a model endpoint).' },
  { path: '/approvals', label: 'Approvals', icon: 'approvals', key: 'p', about: 'Requested response actions; managers decide with a reason (four-eyes) and execute once (simulated).' },
  { path: '/reports', label: 'Reports', icon: 'reports', key: 'r', about: 'Incident reports with their charts; JSON, CSV and PDF downloads; printable summary.' },
  { path: '/audit', label: 'Audit', icon: 'audit', key: 'u', permission: 'audit.read', about: 'Every write and every denied request, with an activity chart.' },
  { path: '/users', label: 'Users', icon: 'users', permission: 'user.manage', about: 'Accounts and roles (admin): create, deactivate, reset with the environment-supplied password.' },
  { path: '/settings', label: 'Settings', icon: 'settings', about: 'Theme, row density, time format, default data source, professor demo mode.' },
  { path: '/security', label: 'Security notes', icon: 'help', hidden: true, about: 'docs/security-notes.md as plain text.' },
  { path: '/entity', label: 'Entity', icon: 'entity', hidden: true, about: 'One host or source IP: activity, rules and the incidents that contain it.' },
];

export const NAV_GROUPS: ReadonlyArray<{ label: string; paths: readonly string[] }> = [
  { label: 'Understand', paths: ['/about', '/study'] },
  { label: 'Monitor', paths: ['/overview', '/executive'] },
  { label: 'Investigate', paths: ['/incidents', '/alerts', '/ask'] },
  { label: 'Respond', paths: ['/approvals', '/reports'] },
  { label: 'Govern', paths: ['/audit', '/users', '/settings'] },
];

/** The rail: groups in order with the items the role may use; a group with none is dropped. */
export function groupNav(items: readonly NavItem[]): Array<{ label: string; items: NavItem[] }> {
  const byPath = new Map(items.filter((n) => !n.hidden).map((n) => [n.path, n]));
  return NAV_GROUPS.map((g) => ({ label: g.label, items: g.paths.flatMap((p) => byPath.get(p) ?? []) })).filter((g) => g.items.length > 0);
}

/** Arrow keys in the rail: the next index (wraps), or null for a key the rail does not handle. */
export function railMove(count: number, current: number, key: string): number | null {
  if (count === 0) return null;
  if (key === 'Home') return 0;
  if (key === 'End') return count - 1;
  if (key === 'ArrowDown') return current < 0 ? 0 : (current + 1) % count;
  if (key === 'ArrowUp') return current < 0 ? count - 1 : (current - 1 + count) % count;
  return null;
}

/**
 * How well `query` matches `text` (higher is better, 0 = no match): whole text 4, prefix 3,
 * prefix of a word 2, substring 1, letters in order 0.5 (3+ letters). Case-insensitive.
 */
export function matchScore(text: string, query: string): number {
  const t = text.toLowerCase();
  const q = query.trim().toLowerCase();
  if (!q) return 1;
  if (t === q) return 4;
  if (t.startsWith(q)) return 3;
  if (t.split(/[\s/._-]+/).some((w) => w.startsWith(q))) return 2;
  if (t.includes(q)) return 1;
  if (q.length < 3) return 0; // two letters in order match almost anything
  let i = 0;
  for (const ch of t) if (ch === q[i]) i += 1;
  return i === q.length ? 0.5 : 0;
}

export interface Rankable {
  label: string;
  keywords?: string;
}

/** Palette filter: keeps matching items, best first; ties keep the given order. Empty query keeps all. */
export function filterRank<T extends Rankable>(items: readonly T[], query: string): T[] {
  if (!query.trim()) return [...items];
  return items
    .map((it, i) => ({ it, i, s: Math.max(matchScore(it.label, query), it.keywords ? matchScore(it.keywords, query) * 0.9 : 0) }))
    .filter((x) => x.s > 0)
    .sort((a, b) => b.s - a.s || a.i - b.i)
    .map((x) => x.it);
}
