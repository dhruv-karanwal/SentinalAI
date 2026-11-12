// Pure helpers for the explainable console (2026-11-13): glossary search (the chat's offline
// answers), the deterministic "What happened" sentence of an incident, distinct incident labels,
// and collapsing repeated alert rows. No model, no network; everything here is unit-tested.

import { GLOSSARY, type GlossaryTerm } from '../content/glossary.ts';
import { fmtDuration, fmtInt, isoUtc, parseEntity } from './format.ts';

const STOP = new Set('a an and are as at be by does do for from how i in is it me of on or the this that to what whats when where which who why with mean means explain tell about here there show shown screen chart'.split(' '));

function words(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9&.\- ]+/g, ' ')
    .split(/\s+/)
    .map((w) => w.replace(/^[.\-]+|[.\-?]+$/g, ''))
    .filter((w) => w.length > 0 && !STOP.has(w));
}

/** Glossary terms ranked for a free-text question (exact term or alias first, then word overlap). */
export function searchGlossary(query: string, terms: readonly GlossaryTerm[] = GLOSSARY, limit = 5): GlossaryTerm[] {
  const q = words(query);
  if (q.length === 0) return [];
  const qs = ` ${q.join(' ')} `;
  const scored = terms.map((t, i) => {
    let score = 0;
    for (const name of [t.term, ...t.aliases]) {
      const n = words(name).join(' ');
      if (!n) continue;
      if (qs.includes(` ${n} `)) score = Math.max(score, 100 + n.length);
    }
    const head = new Set(words(`${t.term} ${t.aliases.join(' ')}`));
    const body = new Set(words(t.definition));
    for (const w of q) {
      if (head.has(w)) score += 10;
      else if (w.length > 3 && body.has(w)) score += 2;
    }
    return { t, score, i };
  });
  return scored
    .filter((s) => s.score >= 10)
    .sort((a, b) => b.score - a.score || a.i - b.i)
    .slice(0, limit)
    .map((s) => s.t);
}

/** The chat's deterministic fallback: the best glossary entry, or an honest "not in the glossary". */
export function glossaryAnswer(query: string): { found: boolean; text: string; terms: GlossaryTerm[] } {
  const hits = searchGlossary(query, GLOSSARY, 3);
  const best = hits[0];
  if (!best) {
    return { found: false, terms: [], text: 'That is not in the glossary, and without the local model I will not guess. Try a term shown with a "?" on the screen, or open About.' };
  }
  const more = hits.slice(1).map((t) => t.term);
  return {
    found: true,
    terms: hits,
    text: `${best.term}: ${best.definition} Why it matters here: ${best.why}${more.length ? ` Related: ${more.join(', ')}.` : ''}`,
  };
}

// ---- incidents -------------------------------------------------------------------------------

export interface IncidentLike {
  incident_id: string;
  severity: string;
  first_ts: string;
  last_ts: string;
  alert_ids: readonly string[];
  detail: {
    detectors?: Record<string, number>;
    entities?: string[];
    /** the host / source IP with the most alerts (summary endpoints); entities is sorted by value */
    main_host?: string | null;
    main_ip?: string | null;
    timeline?: ReadonlyArray<{ rule_name: string | null; rule_id: string | null }>;
  };
}

/** Main host and source IP by alert count, e.g. from the incident analysis graph nodes. */
export interface MainEntities {
  host: string | null;
  ip: string | null;
}

/** The most-alerted host and source IP among graph nodes ({kind: 'host' | 'ip', value, alerts}). */
export function mainFromNodes(nodes: ReadonlyArray<{ kind: string; value: string; alerts: number }>): MainEntities {
  const pick = (kind: string) => {
    let best: { value: string; alerts: number } | null = null;
    for (const n of nodes) if (n.kind === kind && (!best || n.alerts > best.alerts || (n.alerts === best.alerts && n.value < best.value))) best = n;
    return best?.value ?? null;
  };
  return { host: pick('host'), ip: pick('ip') };
}

const DET_NAMES: Record<string, string> = { wazuh: 'Wazuh', suricata: 'Suricata', aminer: 'AMiner', sigma: 'Sigma' };
const DET_ORDER = ['wazuh', 'suricata', 'aminer', 'sigma'];

function joinWords(list: string[]): string {
  if (list.length <= 1) return list.join('');
  return `${list.slice(0, -1).join(', ')} and ${list[list.length - 1]}`;
}

/** "2022-01-24 03:01:07" (UTC, seconds) */
function dataTime(ts: string): string {
  return isoUtc(ts).replace('T', ' ').replace('Z', '');
}

/**
 * The host with the most alerts, else the source IP with the most alerts. Without counts (an old
 * API) the only host or IP is used; with several and no counts there is no "main" one.
 */
export function mainEntity(detail: IncidentLike['detail']): { kind: 'host' | 'IP'; value: string } | null {
  if (detail.main_host) return { kind: 'host', value: detail.main_host };
  if (detail.main_ip) return { kind: 'IP', value: detail.main_ip };
  const e = (detail.entities ?? []).map(parseEntity);
  const hosts = e.filter((x) => x.kind === 'host');
  const ips = e.filter((x) => x.kind === 'ip');
  if (hosts.length === 1) return { kind: 'host', value: hosts[0]!.value };
  if (hosts.length === 0 && ips.length === 1) return { kind: 'IP', value: ips[0]!.value };
  return null;
}

/** A label that tells incidents apart: main host or IP plus the first-seen data time (minutes). */
export function incidentLabel(inc: Pick<IncidentLike, 'incident_id' | 'first_ts' | 'detail'>): string {
  const m = mainEntity(inc.detail);
  const when = `${dataTime(inc.first_ts).slice(0, 16)} UTC`;
  return `${m ? `${m.kind} ${m.value}` : inc.incident_id} · ${when}`;
}

/**
 * One or two plain sentences about an incident, built from its stored data only (never from the
 * model): when, how many alerts from which detectors, which host and source IP, the most frequent
 * rule and why triage rated it as it did.
 */
export function whatHappened(inc: IncidentLike, rule: { row: string; rule: string } | null, main: MainEntities | null = null): string {
  const n = inc.alert_ids.length;
  const start = dataTime(inc.first_ts);
  const end = dataTime(inc.last_ts);
  const endShort = end.slice(0, 10) === start.slice(0, 10) ? end.slice(11) : end;
  const span = (Date.parse(inc.last_ts) - Date.parse(inc.first_ts)) / 1000;
  const rank = (d: string) => (DET_ORDER.includes(d) ? DET_ORDER.indexOf(d) : 99);
  const dets = Object.keys(inc.detail.detectors ?? {}).sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
  const detText = dets.length ? ` from ${joinWords(dets.map((d) => DET_NAMES[d] ?? d))}` : '';
  const ents = (inc.detail.entities ?? []).map(parseEntity);
  const hosts = ents.filter((e) => e.kind === 'host').map((e) => e.value);
  const ips = ents.filter((e) => e.kind === 'ip').map((e) => e.value);
  // name a host / IP only when it is known to be the main one (most alerts) or the only one
  const host = main?.host ?? inc.detail.main_host ?? (hosts.length === 1 ? hosts[0]! : null);
  const ip = main?.ip ?? inc.detail.main_ip ?? (ips.length === 1 ? ips[0]! : null);
  const more = (n: number, what: string) => (n > 1 ? ` (${fmtInt(n)} ${what} in all)` : '');
  let who = '';
  if (host) who += ` concerned ${hosts.length > 1 ? 'mostly ' : ''}host ${host}${more(hosts.length, 'hosts')}`;
  else if (hosts.length) who += ` concerned ${fmtInt(hosts.length)} hosts`;
  if (ip) who += `${who ? ', ' : ' came '}${who && ips.length > 1 ? 'mostly ' : ''}from source IP ${ip}${more(ips.length, 'source IPs')}`;
  else if (ips.length) who += `${who ? ', ' : ' came '}from ${fmtInt(ips.length)} source IPs`;
  let s = `Between ${start} and ${endShort} UTC (data time, ${fmtDuration(Number.isFinite(span) ? span : 0)}), ${fmtInt(n)} alert${n === 1 ? '' : 's'}${detText}${who}.`;
  const timeline = inc.detail.timeline ?? [];
  if (timeline.length) {
    const counts = new Map<string, number>();
    for (const e of timeline) {
      const k = e.rule_name ?? e.rule_id ?? '';
      if (k) counts.set(k, (counts.get(k) ?? 0) + 1);
    }
    let best = '';
    let c = 0;
    for (const [k, v] of counts) if (v > c || (v === c && k < best)) [best, c] = [k, v];
    if (best) s += ` The most frequent rule was "${best}" (${fmtInt(c)} of ${fmtInt(timeline.length)} alerts).`;
  }
  s += rule ? ` Triage rated it ${inc.severity} because ${rule.rule} (rule ${rule.row}).` : ` Triage rated it ${inc.severity}.`;
  return s;
}

// ---- repeated alert rows ---------------------------------------------------------------------

export interface RowLike {
  alert_id: string;
  detector: string;
  rule_id: string | null;
  rule_name: string | null;
  severity: number | null;
  host_ip: string | null;
  src_ip: string | null;
  ts: string;
}

/** Consecutive rows with the same detector, rule, level, host and source IP, as one group. */
export function collapseRuns<T extends RowLike>(rows: readonly T[]): Array<{ first: T; last: T; count: number }> {
  const out: Array<{ first: T; last: T; count: number }> = [];
  const key = (r: T) => [r.detector, r.rule_id, r.rule_name, r.severity, r.host_ip, r.src_ip].join('\u0000');
  for (const r of rows) {
    const g = out[out.length - 1];
    if (g && key(g.first) === key(r)) {
      g.last = r;
      g.count += 1;
    } else out.push({ first: r, last: r, count: 1 });
  }
  return out;
}

/** incidentLabel for a list, made unique: a repeated label gets the incident id appended. */
export function distinctLabels<T extends Pick<IncidentLike, 'incident_id' | 'first_ts' | 'detail'>>(rows: readonly T[]): Map<string, string> {
  const base = rows.map((r) => incidentLabel(r));
  const seen = new Map<string, number>();
  for (const b of base) seen.set(b, (seen.get(b) ?? 0) + 1);
  return new Map(rows.map((r, i) => [r.incident_id, (seen.get(base[i]!) ?? 0) > 1 ? `${base[i]} · ${r.incident_id}` : base[i]!]));
}
