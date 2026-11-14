// About ("How SentinelAI works") as a scroll story (DESIGN.md 13.3). The landing page in Professor
// demo mode. Hero: the six-stage pipeline with alert packets flowing along SVG paths and live
// counters from the API; then sections that reveal on scroll with a sticky stepper: the problem,
// the stages in detail, the study (interactive: pick an alert source, watch the fixed agent receive
// it, four arms as lanes), the verifier demo (the real quote rule on a labelled SAMPLE), the live
// results status (never a number that is not in a result file), screen cards, limits, glossary.

import { useEffect, useMemo, useRef, useState } from 'react';

import { api, can, type Overview, type StudyResults } from '../api.ts';
import { Reveal, useSeen } from '../components/motion.tsx';
import { Term } from '../components/Term.tsx';
import { Button, ErrorNotice, SkeletonLines } from '../components/ui.tsx';
import { GLOSSARY } from '../content/glossary.ts';
import { ARMS, HERO_STAGES, LIMITS, PIPELINE, PROBLEM, SCREEN_GUIDE, STUDY_QUESTION, STUDY_SOURCES, VERIFIER_SAMPLE, quoteSupported } from '../content/about.ts';
import { useApp, useLoad } from '../hooks.ts';
import { Icon } from '../icons.tsx';
import { fmtInt } from '../lib/format.ts';
import { searchGlossary } from '../lib/explain.ts';
import { activeSection, prefersReducedMotion } from '../lib/motion.ts';

const SECTIONS = [
  ['ab-hero', 'Start'],
  ['ab-problem', 'The problem'],
  ['ab-pipe', 'The pipeline'],
  ['ab-study', 'The study'],
  ['ab-verify', 'The verifier'],
  ['ab-results', 'Results so far'],
  ['ab-screens', 'The screens'],
  ['ab-limits', 'Limits'],
  ['ab-gloss', 'Glossary'],
] as const;

export function AboutScreen({ onTour }: { onTour: () => void }) {
  const { session, scenario } = useApp();
  const mayReadStudy = can(session.role, 'read.raw');
  const study = useLoad((signal) => (mayReadStudy ? api.study(signal) : Promise.resolve(null)), [mayReadStudy]);
  const overview = useLoad((signal) => (scenario ? api.overview(scenario, signal) : Promise.resolve(null)), [scenario]);
  const scroller = useRef<HTMLDivElement | null>(null);
  const [current, setCurrent] = useState(0);

  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    let raf = 0;
    const measure = () => {
      raf = 0;
      const top = el.getBoundingClientRect().top;
      const tops = SECTIONS.map(([id]) => (document.getElementById(id)?.getBoundingClientRect().top ?? 1e9) - top);
      setCurrent(Math.max(0, activeSection(tops, el.clientHeight * 0.35)));
    };
    const onScroll = () => {
      if (!raf) raf = requestAnimationFrame(measure);
    };
    measure();
    el.addEventListener('scroll', onScroll, { passive: true });
    return () => {
      el.removeEventListener('scroll', onScroll);
      cancelAnimationFrame(raf);
    };
  }, []);

  const screens = SCREEN_GUIDE.filter((g) => (g.path === '/study' ? mayReadStudy : g.path === '/ask' ? can(session.role, 'copilot.ask') : true));

  return (
    <div className="page about" ref={scroller}>
      <div className="page-body">
        <div className="story">
          <nav aria-label="Sections of this page">
            <ol className="story-steps">
              {SECTIONS.map(([id, name], i) => (
                <li key={id}>
                  <a
                    href={`#/about`}
                    aria-current={i === current ? 'step' : undefined}
                    onClick={(e) => {
                      e.preventDefault();
                      document.getElementById(id)?.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
                    }}
                  >
                    {name}
                  </a>
                </li>
              ))}
            </ol>
          </nav>
          <div className="story-main">
            <Hero overview={overview.data} loading={overview.loading} onTour={onTour} scenario={scenario} />

            <Reveal as="section" className="story-sec" id="ab-problem" aria-labelledby="ab-problem-t">
              <div className="kicker">01 · The problem</div>
              <h2 id="ab-problem-t">Too many alerts, spread over too many tools</h2>
              <p>{PROBLEM}</p>
            </Reveal>

            <Reveal as="section" className="story-sec" id="ab-pipe" aria-labelledby="ab-pipe-t">
              <div className="kicker">02 · The pipeline</div>
              <h2 id="ab-pipe-t">Five stages, each a real part of the code</h2>
              <p className="faint">Each box names the real components (backend/app). Data flows left to right; the console reads the stores at every stage.</p>
              <ol className="pipe" aria-label="Pipeline stages">
                {PIPELINE.map((s, i) => (
                  <Reveal as="li" key={s.n} i={i} className="pipe-stage">
                    <div className="pipe-box">
                      <div className="pipe-n num">{s.n}</div>
                      <div className="pipe-name">{s.name}</div>
                      <p className="pipe-plain">{s.plain}</p>
                      <ul className="pipe-comp">
                        {s.components.map((c) => (
                          <li key={c} className="mono">
                            {c}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </Reveal>
                ))}
              </ol>
            </Reveal>

            <Reveal as="section" className="story-sec" id="ab-study" aria-labelledby="ab-study-t">
              <div className="kicker">03 · The study</div>
              <h2 id="ab-study-t">Same investigator, different alerts</h2>
              <p className="about-question">{STUDY_QUESTION}</p>
              <StudyDiagram overview={overview.data} />
              <p className="about-small">
                The <Term id="agent">investigation agent</Term> and the <Term id="multi-agent">multi-agent graph</Term> run on the same cases under a <Term id="matched-budget">matched budget</Term>; each is scored before
                and after the <Term id="verifier">evidence verifier</Term>, next to <Term id="baseline">baselines</Term>. Headline: <Term id="coverage">coverage</Term> of{' '}
                <Term id="reachable-phase">alert-reachable phases</Term> after the verifier.
              </p>
            </Reveal>

            <Reveal as="section" className="story-sec" id="ab-verify" aria-labelledby="ab-verify-t">
              <div className="kicker">04 · The verifier</div>
              <h2 id="ab-verify-t">Every claim is checked against the evidence</h2>
              <VerifierDemo />
            </Reveal>

            <Reveal as="section" className="story-sec" id="ab-results" aria-labelledby="ab-results-t">
              <div className="kicker">05 · Results so far</div>
              <h2 id="ab-results-t">Where the study stands</h2>
              <ResultsStatus allowed={mayReadStudy} data={study.data} loading={study.loading} error={study.error} reload={study.reload} />
            </Reveal>

            <Reveal as="section" className="story-sec" id="ab-screens" aria-labelledby="ab-screens-t">
              <div className="kicker">06 · The screens</div>
              <h2 id="ab-screens-t">What each screen shows, and why</h2>
              <ul className="tilt-grid">
                {screens.map((g, i) => (
                  <Reveal as="li" key={g.path} i={i}>
                    <a href={`#${g.path}`}>
                      <span className="tilt-name">
                        {g.name} <Icon name="chevronRight" />
                      </span>
                      <span>{g.what}</span>
                      <span className="faint">{g.why}</span>
                    </a>
                  </Reveal>
                ))}
              </ul>
            </Reveal>

            <Reveal as="section" className="story-sec" id="ab-limits" aria-labelledby="ab-limits-t">
              <div className="kicker">07 · Limits</div>
              <h2 id="ab-limits-t">Limits and honesty notes</h2>
              <ul className="limits">
                {LIMITS.map((l) => (
                  <li key={l}>{l}</li>
                ))}
              </ul>
            </Reveal>

            <Glossary />
          </div>
        </div>
      </div>
    </div>
  );
}

function Hero({ overview, loading, onTour, scenario }: { overview: Overview | null; loading: boolean; onTour: () => void; scenario: string | null }) {
  const W = 960;
  const step = 160;
  const x0 = 80;
  const r = 24;
  return (
    <section className="hero" id="ab-hero" aria-labelledby="ab-hero-t">
      <div className="kicker">SentinelAI · AI-assisted security operations</div>
      <h1 id="ab-hero-t">From raw alerts to a checked, human-approved answer</h1>
      <p className="hero-lead">
        A research console that replays the <Term id="ait-ads">AIT-ADS</Term> alert dataset through a full security-operations pipeline, lets a local AI investigate with citations, and checks every
        citation before a person acts.
      </p>
      <svg className="pipe-svg" viewBox={`0 0 ${W} 150`} role="img" aria-label={`Pipeline: ${HERO_STAGES.map((s) => s.name).join(', then ')}. Animated alert packets flow from stage to stage.`}>
        <line className="track" x1={x0} y1={50} x2={x0 + step * (HERO_STAGES.length - 1)} y2={50} />
        {HERO_STAGES.slice(0, -1).map((_, i) => (
          <circle
            key={`p${i}`}
            className="pkt"
            data-tone={(['wazuh', 'aminer', 'high', 'ref', 'wazuh'] as const)[i]}
            cx={x0 + i * step + r}
            cy={50}
            r={4}
            style={{ '--seg': i, '--hop': `${step - 2 * r}px` } as React.CSSProperties}
          />
        ))}
        {HERO_STAGES.map((s, i) => (
          <g key={s.name} transform={`translate(${x0 + i * step} 50)`}>
            <circle className="node" r={r} />
            <circle className="node-glow" r={r + 3} style={{ '--s': i } as React.CSSProperties} />
            <text textAnchor="middle" dy={5} className="sub" style={{ font: '600 12px var(--font-mono)' }}>
              {String(i + 1).padStart(2, '0')}
            </text>
            <text textAnchor="middle" y={r + 22}>
              {s.name}
            </text>
            <text textAnchor="middle" y={r + 38} className="sub">
              {s.sub}
            </text>
          </g>
        ))}
      </svg>
      <div className="hero-kpis" aria-busy={loading && !overview}>
        <Kpi k={`alerts stored${scenario ? ` (${scenario})` : ''}`} v={overview?.alerts} />
        <Kpi k="incidents built by triage" v={overview?.status.incidents} />
        <Kpi k="detectors with alerts" v={overview?.detectors.filter((d) => d.alerts > 0).length} />
      </div>
      <div className="hero-actions">
        <Button kind="primary" icon="play" onClick={onTour}>
          Start here: 6-stop tour
        </Button>
        <a className="btn" href="#/overview">
          Open the Overview
        </a>
      </div>
    </section>
  );
}

function Kpi({ k, v }: { k: string; v: number | undefined }) {
  return (
    <div className="kpi">
      <div className="kpi-v">{v === undefined ? <span className="faint">-</span> : fmtInt(v)}</div>
      <div className="kpi-k">{k}</div>
    </div>
  );
}

/** Schematic of the study: the chosen alert source feeds the fixed agent; four arms as lanes. */
function StudyDiagram({ overview }: { overview: Overview | null }) {
  const [src, setSrc] = useState('fused');
  const opt = STUDY_SOURCES.find((s) => s.id === src) ?? STUDY_SOURCES[0]!;
  const cells = useMemo(() => feedCells(src, overview), [src, overview]);
  return (
    <div>
      <div className="study-src" role="group" aria-label="Alert source given to the agent">
        {STUDY_SOURCES.map((s) => (
          <button key={s.id} type="button" className="chip" aria-pressed={s.id === src} onClick={() => setSrc(s.id)}>
            {s.label}
          </button>
        ))}
      </div>
      <div className="study-flow">
        <div>
          <div className="feed" key={src} aria-hidden="true">
            {cells.map((c, n) => (
              <i key={n} style={{ '--tone': `var(--${c.tone})`, '--n': n } as React.CSSProperties} data-hollow={c.hollow ? '' : undefined} data-mark={c.mark ? '' : undefined} />
            ))}
          </div>
          <p className="feed-cap">
            <strong>{opt.label}:</strong> {opt.what} <span className="sample-tag">SCHEMATIC</span>{' '}
            {src === 'fused' && overview ? `48 squares in the real detector shares of ${overview.scenario}.` : 'Squares show the kind of alerts, not counts.'}
          </p>
        </div>
        <div className="agent-box" aria-hidden="true">
          <div>
            fixed agent
            <small>same model, prompt, budget</small>
          </div>
        </div>
        <div className="lanes" role="list" aria-label="The four arms scored on every case">
          {ARMS.map((a, l) => (
            <div className="lane" role="listitem" key={a.id}>
              <span className="mono">{a.label}</span>
              <span className="lane-track" data-verified={a.verified ? '' : undefined} aria-label={a.verified ? 'claims pass the verifier; unsupported ones are dropped' : 'raw answer, nothing dropped'}>
                {[0, 1, 2, 3].map((k) => (
                  <b key={k} style={{ '--k': k, '--l': l } as React.CSSProperties} />
                ))}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

interface Cell {
  tone: string;
  hollow?: boolean;
  mark?: boolean;
}

function feedCells(src: string, overview: Overview | null): Cell[] {
  const N = 48;
  const det = (d: string): Cell => ({ tone: `det-${d}` });
  if (src === 'wazuh' || src === 'suricata' || src === 'aminer') return Array.from({ length: N }, () => det(src));
  if (src === 'noise') return Array.from({ length: N }, () => ({ tone: 'text-faint', hollow: true }));
  const counts = (overview?.detectors ?? []).filter((d) => ['wazuh', 'suricata', 'aminer'].includes(d.detector) && d.alerts > 0);
  const total = counts.reduce((a, d) => a + d.alerts, 0);
  // largest-remainder split of N squares by real shares (fused); equal thirds before data arrives
  const shares = total ? counts.map((d) => ({ d: d.detector, x: (d.alerts / total) * N })) : ['wazuh', 'suricata', 'aminer'].map((d) => ({ d, x: N / 3 }));
  const base = shares.map((s) => ({ ...s, n: Math.floor(s.x) }));
  let left = N - base.reduce((a, s) => a + s.n, 0);
  [...base].sort((a, b) => (b.x - b.n) - (a.x - a.n)).forEach((s) => left-- > 0 && (s.n += 1));
  const fused = base.flatMap((s) => Array.from({ length: s.n }, () => det(s.d)));
  if (src === 'fused') return fused;
  if (src === 'oracle') return fused.map((c, i) => (i % 4 === 0 ? { ...c, mark: true } : { tone: 'border' })).slice(0, N);
  // shuffled: deterministic interleave of the fused pool
  return fused.map((_, i) => fused[(i * 29) % fused.length]!);
}

/** The verifier on a labelled SAMPLE line, with the real quote rule; the reader can type a quote. */
function VerifierDemo() {
  const ref = useRef<HTMLDivElement | null>(null);
  const seen = useSeen(ref);
  const [phase, setPhase] = useState(0); // 0 idle, 1 scanning claim 1, 2 claim 1 done, 3 scanning 2, 4 done
  const [own, setOwn] = useState('');
  const run = () => {
    if (prefersReducedMotion()) return setPhase(4);
    setPhase(1);
    [2, 3, 4].forEach((p, i) => window.setTimeout(() => setPhase(p), 900 * (i + 1)));
  };
  useEffect(() => {
    if (seen && phase === 0) run();
  }, [seen]);
  const results = VERIFIER_SAMPLE.claims.map((c) => quoteSupported(VERIFIER_SAMPLE.line, c.quote));
  const ownResult = own ? quoteSupported(VERIFIER_SAMPLE.line, own) : null;
  return (
    <div ref={ref}>
      <p>
        The agent must back each claim with a quote from a log line it cited. The verifier keeps a quote only if it is an exact, case-sensitive part of that line (at least 8 characters) and drops
        the rest, counting each drop. <span className="sample-tag">SAMPLE: synthetic line, not from a run</span>
      </p>
      <div className="vdemo">
        <div>
          <div className="k faint" style={{ fontSize: 'var(--fs-micro)', marginBottom: 4 }}>
            Evidence: cited log line
          </div>
          <div className="vline" data-scanning={phase === 1 || phase === 3 ? '' : undefined}>
            {VERIFIER_SAMPLE.line}
          </div>
          <div style={{ marginTop: 'var(--sp-8)' }}>
            <Button icon="refresh" onClick={run}>
              Run the check again
            </Button>
          </div>
        </div>
        <div style={{ display: 'grid', gap: 'var(--sp-8)' }}>
          {VERIFIER_SAMPLE.claims.map((c, i) => {
            const done = phase >= (i === 0 ? 2 : 4);
            const r = results[i]!;
            return (
              <div key={c.quote} className="vcard" data-v={done ? (r.kept ? 'kept' : 'dropped') : undefined} aria-live="polite">
                <div className="vclaim">{c.text}</div>
                <div className="mono faint" style={{ fontSize: 'var(--fs-small)' }}>
                  quote: "{c.quote}"
                </div>
                {done && <span className="vtag">{r.reason}</span>}
              </div>
            );
          })}
          <label className="label" htmlFor="v-own">
            Try your own quote against the line
          </label>
          <input id="v-own" className="input mono" value={own} maxLength={120} onChange={(e) => setOwn(e.target.value)} placeholder='e.g. "POST /wp-login.php"' />
          {ownResult && (
            <div className="vcard" data-v={ownResult.kept ? 'kept' : 'dropped'} role="status">
              <span className="vtag">{ownResult.reason}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Glossary() {
  const [q, setQ] = useState('');
  const terms = useMemo(() => {
    if (!q.trim()) return GLOSSARY;
    const hits = searchGlossary(q, GLOSSARY, 40);
    const needle = q.trim().toLowerCase();
    const sub = GLOSSARY.filter((t) => !hits.includes(t) && `${t.term} ${t.definition}`.toLowerCase().includes(needle));
    return [...hits, ...sub];
  }, [q]);
  return (
    <Reveal as="section" className="story-sec" id="ab-gloss" aria-labelledby="ab-gloss-t">
      <div className="kicker">08 · Glossary</div>
      <h2 id="ab-gloss-t">Every term, in plain words</h2>
      <div className="search" style={{ maxWidth: 360 }}>
        <Icon name="search" />
        <label className="visually-hidden" htmlFor="gl-q">
          Filter the glossary
        </label>
        <input id="gl-q" className="input" placeholder={`Filter ${GLOSSARY.length} terms`} value={q} maxLength={80} onChange={(e) => setQ(e.target.value)} />
      </div>
      {terms.length === 0 ? (
        <p className="faint">No term matches "{q}".</p>
      ) : (
        <dl className="glossary">
          {terms.map((t) => (
            <div key={t.id} className="gl-row" id={`gl-${t.id}`}>
              <dt>{t.term}</dt>
              <dd>
                {t.definition} <span className="faint">Why it matters here: {t.why}</span>
                {t.see && (
                  <>
                    {' '}
                    <a href={`#${t.see}`}>Open</a>
                  </>
                )}
              </dd>
            </div>
          ))}
        </dl>
      )}
    </Reveal>
  );
}

function ResultsStatus({ allowed, data, loading, error, reload }: { allowed: boolean; data: StudyResults | null; loading: boolean; error: import('../api.ts').ApiError | null; reload: () => void }) {
  if (!allowed) return <p className="faint">Your role cannot read study results; the Study page is for analysts, managers and admins.</p>;
  if (error && !data) return <ErrorNotice what="study results" error={error} onRetry={reload} />;
  if (!data) return loading ? <SkeletonLines lines={2} /> : null;
  const part = (r: StudyResults['runs'][number]) => r.study_part ?? (r.split === 'held-out' ? 'held-out' : 'pilot');
  const pilot = data.runs.filter((r) => part(r) === 'pilot');
  const final = data.runs.filter((r) => part(r) === 'held-out');
  return (
    <div className="results-status">
      <div className="rs-cell">
        <div className="k">
          <Term id="pilot">Pilot</Term> (dev scenarios)
        </div>
        <div className="v num">{pilot.length ? `${fmtInt(pilot.length)} finished run${pilot.length === 1 ? '' : 's'}` : 'none finished yet'}</div>
        <div className="s">Pilot numbers, not paper results.</div>
      </div>
      <div className="rs-cell">
        <div className="k">
          Final (<Term id="held-out">held-out scenarios</Term>)
        </div>
        <div className="v num">{final.length ? `${fmtInt(final.length)} finished run${final.length === 1 ? '' : 's'}` : 'not started'}</div>
        <div className="s">Only after the protocol is frozen.</div>
      </div>
      <div className="rs-cell">
        <div className="k">In progress</div>
        <div className="v num">
          {fmtInt(data.incomplete_runs)} run{data.incomplete_runs === 1 ? '' : 's'} without scores yet
        </div>
        <div className="s">{data.excluded_fake_runs ? `${fmtInt(data.excluded_fake_runs)} plumbing-check runs (fake model) not counted.` : 'Runs with a fake model are never counted.'}</div>
      </div>
      <p className="about-small rs-note">
        {pilot.length || final.length ? (
          <>
            The numbers themselves are on the <a href="#/study">Study page</a>, read from the run files; nothing here is typed in.
          </>
        ) : (
          <>
            When a run finishes, the <a href="#/study">Study page</a> will show, per alert source and arm: coverage of the reachable attack phases, citation precision, and the unsupported-claim rate
            before and after the verifier, next to the baselines. Until then it is empty on purpose.
          </>
        )}
      </p>
    </div>
  );
}
