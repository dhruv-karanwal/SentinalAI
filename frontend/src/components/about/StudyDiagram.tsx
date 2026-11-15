// The study as an interactive diagram (DESIGN.md 7): pick the alert source (radio group, arrow
// keys), the fixed agent in the middle, the four arms on the right; the verified arms drop their
// unsupported citations at the verifier. Fused uses the real detector shares of the scenario;
// everything else is SCHEMATIC. A source change animates once.

import { useMemo, useState, type KeyboardEvent } from 'react';

import type { Overview } from '../../api.ts';
import { ARMS, STUDY_QUESTION, STUDY_SOURCES } from '../../content/about.ts';
import { interleave, shareSplit } from '../../lib/flow.ts';
import { fmtInt } from '../../lib/format.ts';
import { Term } from '../Term.tsx';
import { detectorName } from '../ui.tsx';
import { FLOW_DETECTORS } from './PipelineFlow.tsx';

const CELLS = 48;
/** schematic citations per arm, and how many the verifier drops in the verified arms */
const CITED = 6;
const DROPPED = 2;

type Cell = { det: string; kind?: 'noise' | 'empty' };

function feedCells(src: string, overview: Overview | null): Cell[] {
  if (src === 'wazuh' || src === 'suricata' || src === 'aminer') return Array.from({ length: CELLS }, () => ({ det: src }));
  if (src === 'noise') return Array.from({ length: CELLS }, () => ({ det: 'none', kind: 'noise' as const }));
  const counts = FLOW_DETECTORS.map((d) => ({ key: d, count: overview?.detectors.find((r) => r.detector === d)?.alerts ?? 0 }));
  const shares = shareSplit(counts, CELLS);
  if (src === 'fused') return shares.flatMap((s) => Array.from({ length: s.n }, () => ({ det: s.key })));
  const mixed = interleave(shares).map((det) => ({ det }));
  // oracle: only the alerts linked to an attack step remain (schematic: every fourth)
  if (src === 'oracle') return mixed.map((c, i) => (i % 4 === 0 ? c : { det: 'none', kind: 'empty' as const }));
  return mixed; // shuffled: a random draw of the same size, shown interleaved
}

export function StudyDiagram({ overview }: { overview: Overview | null }) {
  const [src, setSrc] = useState('fused');
  const opt = STUDY_SOURCES.find((s) => s.id === src) ?? STUDY_SOURCES[0]!;
  const cells = useMemo(() => feedCells(src, overview), [src, overview]);

  const shares = useMemo(() => {
    if (!overview) return null;
    const rows = FLOW_DETECTORS.map((d) => ({ d, n: overview.detectors.find((r) => r.detector === d)?.alerts ?? 0 }));
    const total = rows.reduce((a, r) => a + r.n, 0);
    return total ? rows.map((r) => `${detectorName(r.d)} ${fmtInt(r.n)}`).join(', ') : null;
  }, [overview]);

  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const i = STUDY_SOURCES.findIndex((s) => s.id === src);
    const n = STUDY_SOURCES.length;
    const to = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? (i + 1) % n : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? (i - 1 + n) % n : e.key === 'Home' ? 0 : e.key === 'End' ? n - 1 : -1;
    const next = STUDY_SOURCES[to];
    if (!next) return;
    e.preventDefault();
    setSrc(next.id);
    document.getElementById(`ab-src-${next.id}`)?.focus();
  };

  return (
    <div className="ab-study">
      <p className="ab-question">{STUDY_QUESTION}</p>
      <div className="ab-src" role="radiogroup" aria-label="Alert source given to the agent" onKeyDown={onKey}>
        {STUDY_SOURCES.map((s) => (
          <button
            key={s.id}
            id={`ab-src-${s.id}`}
            type="button"
            role="radio"
            className="btn"
            aria-checked={s.id === src}
            tabIndex={s.id === src ? 0 : -1}
            onClick={() => setSrc(s.id)}
          >
            {s.label}
          </button>
        ))}
      </div>

      <div className="ab-study-grid">
        <div className="ab-feed-col">
          <div className="ab-col-label">Alert source</div>
          <div className="ab-feed" key={src} aria-hidden="true">
            {cells.map((c, n) => (
              <i key={n} className="ab-mark" data-det={c.det} data-kind={c.kind} style={{ '--i': n } as React.CSSProperties} />
            ))}
          </div>
          <p className="ab-cap" aria-live="polite">
            <strong>
              <Term id={(FLOW_DETECTORS as readonly string[]).includes(src) ? src : opt.term}>{opt.label}</Term>
            </strong>{' '}
            {opt.what}
          </p>
          <p className="ab-cap faint">
            {src === 'fused' && shares && overview
              ? `${CELLS} marks in the real detector shares of ${overview.scenario} (${shares} alerts stored).`
              : 'Marks show the kind of alerts, not counts.'}
          </p>
        </div>

        <div className="ab-agent">
          <div className="ab-col-label">Held fixed</div>
          <div className="ab-agent-box">
            <strong>
              <Term id="agent">Investigation agent</Term>
            </strong>
            <span className="faint">Same model, prompt and budget on every source</span>
          </div>
        </div>

        <div className="ab-arms-col">
          <div className="ab-col-label">Four arms, scored on every case</div>
          <ol className="ab-arms" key={src}>
            {ARMS.map((a) => (
              <li key={a.id} className="ab-arm">
                <span className="ab-arm-name">{a.label}</span>
                <span className="ab-arm-track" aria-hidden="true">
                  {Array.from({ length: CITED }, (_, k) => {
                    const drop = a.verified && k >= CITED - DROPPED;
                    return (
                      <span key={k} className="ab-cite-slot">
                        {a.verified && k === CITED - DROPPED && <span className="ab-verifier-rule" />}
                        <i className="ab-cite" data-dropped={drop ? '' : undefined} style={{ '--i': k } as React.CSSProperties} />
                      </span>
                    );
                  })}
                </span>
                <span className="ab-arm-note">{a.verified ? `${DROPPED} dropped` : 'nothing checked'}</span>
              </li>
            ))}
          </ol>
        </div>
      </div>
      <p className="ab-cap">
        <span className="ab-tag">Schematic</span> Filled marks are citations the answer keeps; hollow, struck marks are citations the{' '}
        <Term id="verifier">verifier</Term> drops because the evidence does not support them. Both arms of each pair are scored, before and after the verifier, next to{' '}
        <Term id="baseline">baselines</Term>, under a <Term id="matched-budget">matched budget</Term>. Headline: <Term id="coverage">coverage</Term> of{' '}
        <Term id="reachable-phase">alert-reachable phases</Term> after the verifier.
      </p>
    </div>
  );
}
