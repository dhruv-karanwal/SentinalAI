// Split untrusted text into plain and matched segments. The caller renders each segment as a
// text node (matched ones inside <mark>), so log text never becomes markup.

export interface Segment {
  text: string;
  hit: boolean;
}

/** Search text -> needles: whitespace-separated tokens, at least 2 characters, de-duplicated. */
export function needlesFromQuery(query: string): string[] {
  const out: string[] = [];
  for (const tok of query.split(/\s+/)) {
    const t = tok.replace(/^["']+|["']+$/g, '');
    if (t.length >= 2 && !out.includes(t)) out.push(t);
  }
  return out;
}

export function splitHighlight(text: string, needles: readonly string[], caseSensitive = false): Segment[] {
  const active = needles.filter((n) => n.length > 0);
  if (text.length === 0) return [];
  if (active.length === 0) return [{ text, hit: false }];
  const hay = caseSensitive ? text : text.toLowerCase();
  const marks = new Uint8Array(text.length);
  for (const raw of active) {
    const needle = caseSensitive ? raw : raw.toLowerCase();
    let from = 0;
    for (;;) {
      const i = hay.indexOf(needle, from);
      if (i < 0) break;
      marks.fill(1, i, i + needle.length);
      from = i + needle.length;
    }
  }
  const out: Segment[] = [];
  let start = 0;
  for (let i = 1; i <= text.length; i++) {
    if (i === text.length || marks[i] !== marks[start]) {
      out.push({ text: text.slice(start, i), hit: marks[start] === 1 });
      start = i;
    }
  }
  return out;
}
