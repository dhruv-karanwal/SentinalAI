// Pure formatting helpers. No DOM, no React: tested with `node --test`.

export function fmtInt(n: number): string {
  const s = String(Math.trunc(Math.abs(n)));
  const grouped = s.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return n < 0 ? `-${grouped}` : grouped;
}

/** Absolute UTC time in ISO form with seconds, e.g. 2022-01-21T00:02:27Z. Invalid input is returned as is. */
export function isoUtc(ts: string | number | Date): string {
  const d = ts instanceof Date ? ts : new Date(ts);
  if (Number.isNaN(d.getTime())) return String(ts);
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** Time in the chosen format: iso = 2022-01-21T00:02:27Z, short = 2022-01-21 00:02:27 (both UTC). */
export function fmtTime(ts: string | number | Date, format: 'iso' | 'short' = 'iso'): string {
  const iso = isoUtc(ts);
  if (format === 'iso' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(iso)) return iso;
  return iso.replace('T', ' ').replace('Z', '');
}

/** A bin width as a short unit: "10 s", "5 min", "1 h", "3 h", "1 d"; other values as a duration. */
export function fmtStep(seconds: number): string {
  const s = Math.round(seconds);
  if (s > 0 && s % 86400 === 0) return `${s / 86400} d`;
  if (s > 0 && s % 3600 === 0) return `${s / 3600} h`;
  if (s > 0 && s % 60 === 0 && s < 3600) return `${s / 60} min`;
  if (s > 0 && s < 60) return `${s} s`;
  return fmtDuration(s);
}

export function epochSeconds(ts: string): number {
  return Date.parse(ts) / 1000;
}

/** Duration with units: "0 s", "42 s", "3 min 42 s", "1 h 02 min", "2 d 04 h". */
export function fmtDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${String(s % 60).padStart(2, '0')} s`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ${String(Math.floor((s % 3600) / 60)).padStart(2, '0')} min`;
  return `${Math.floor(s / 86400)} d ${String(Math.floor((s % 86400) / 3600)).padStart(2, '0')} h`;
}

/** Relative time for hover text: "12 s ago", "5 min ago", "3 h ago", "17 d ago", "4 y ago", "in 2 h". */
export function relTime(ts: string | number | Date, now: number = Date.now()): string {
  const t = ts instanceof Date ? ts.getTime() : typeof ts === 'number' ? ts : Date.parse(ts);
  if (Number.isNaN(t)) return '';
  const diff = Math.round((now - t) / 1000);
  const a = Math.abs(diff);
  let text: string;
  if (a < 60) text = `${a} s`;
  else if (a < 3600) text = `${Math.floor(a / 60)} min`;
  else if (a < 86400) text = `${Math.floor(a / 3600)} h`;
  else if (a < 86400 * 365) text = `${Math.floor(a / 86400)} d`;
  else text = `${Math.floor(a / (86400 * 365))} y`;
  return diff >= 0 ? `${text} ago` : `in ${text}`;
}

export type Severity = 'High' | 'Medium' | 'Low';

/** High first. Unknown values sort last. */
export function severityRank(sev: string): number {
  const v = sev.toLowerCase();
  return v === 'high' ? 0 : v === 'medium' ? 1 : v === 'low' ? 2 : 3;
}

const STATUS_ORDER = ['open', 'investigating', 'contained', 'closed'];

export function statusRank(status: string): number {
  const i = STATUS_ORDER.indexOf(status);
  return i < 0 ? STATUS_ORDER.length : i;
}

export interface QueueKey {
  severity: string;
  status: string;
  last_ts: string;
}

/** Default queue order: severity (High first), then status (open first), then last seen (newest first). */
export function compareQueue(a: QueueKey, b: QueueKey): number {
  return (
    severityRank(a.severity) - severityRank(b.severity) ||
    statusRank(a.status) - statusRank(b.status) ||
    (a.last_ts < b.last_ts ? 1 : a.last_ts > b.last_ts ? -1 : 0)
  );
}

export type SortDir = 'asc' | 'desc';

/** Stable sort by a key function; numbers numerically, strings by code unit; null/undefined last. */
export function sortBy<T>(rows: readonly T[], key: (row: T) => string | number | null | undefined, dir: SortDir): T[] {
  const sign = dir === 'asc' ? 1 : -1;
  return rows
    .map((row, i) => ({ row, i, k: key(row) }))
    .sort((x, y) => {
      if (x.k == null && y.k == null) return x.i - y.i;
      if (x.k == null) return 1;
      if (y.k == null) return -1;
      if (x.k < y.k) return -sign;
      if (x.k > y.k) return sign;
      return x.i - y.i;
    })
    .map((x) => x.row);
}

/** "host:10.0.0.1" -> { kind: "host", value: "10.0.0.1" } */
export function parseEntity(entity: string): { kind: string; value: string } {
  const i = entity.indexOf(':');
  return i < 0 ? { kind: '', value: entity } : { kind: entity.slice(0, i), value: entity.slice(i + 1) };
}
