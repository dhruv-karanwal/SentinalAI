// About ("How SentinelAI works"): the page a first-time reader starts on (Professor demo mode
// lands here). The problem, the five pipeline stages with the real component names, the one study
// question, what each screen shows (click to open), the live results status read from
// /study/results (pilot vs final, never invented), limits and honesty notes, and the glossary.

import { useMemo, useState } from 'react';

import { api, can, type StudyResults } from '../api.ts';
import { Term } from '../components/Term.tsx';
import { Button, ErrorNotice, SkeletonLines } from '../components/ui.tsx';
import { GLOSSARY } from '../content/glossary.ts';
import { LIMITS, PIPELINE, PROBLEM, SCREEN_GUIDE, STUDY_QUESTION } from '../content/about.ts';
import { useApp, useLoad } from '../hooks.ts';
import { Icon } from '../icons.tsx';
import { fmtInt } from '../lib/format.ts';
import { searchGlossary } from '../lib/explain.ts';

export function AboutScreen({ onTour }: { onTour: () => void }) {
  const { session } = useApp();
  const mayReadStudy = can(session.role, 'read.raw');
  const study = useLoad((signal) => (mayReadStudy ? api.study(signal) : Promise.resolve(null)), [mayReadStudy]);
  const [q, setQ] = useState('');
  const terms = useMemo(() => {
    if (!q.trim()) return GLOSSARY;
    const hits = searchGlossary(q, GLOSSARY, 40);
    const needle = q.trim().toLowerCase();
    const sub = GLOSSARY.filter((t) => !hits.includes(t) && `${t.term} ${t.definition}`.toLowerCase().includes(needle));
    return [...hits, ...sub];
  }, [q]);
  const screens = SCREEN_GUIDE.filter((g) => (g.path === '/study' ? mayReadStudy : g.path === '/ask' ? can(session.role, 'copilot.ask') : true));

  return (
    <div className="page about">
      <div className="page-head">
        <h1>How SentinelAI works</h1>
        <span className="muted">A guide for a first-time reader: five minutes, no security background needed.</span>
        <span className="spacer" />
        <Button kind="primary" icon="play" onClick={onTour}>
          Start here: 6-stop tour
        </Button>
      </div>
      <div className="page-body about-body">
        <section className="about-sec" aria-labelledby="ab-problem">
          <h2 id="ab-problem">The problem</h2>
          <p className="about-lead">{PROBLEM}</p>
        </section>

        <section className="about-sec" aria-labelledby="ab-pipe">
          <h2 id="ab-pipe">The pipeline, in five stages</h2>
          <p className="faint about-small">Each box names the real components in the code (backend/app). Data flows left to right; the console reads the stores at every stage.</p>
          <ol className="pipe" aria-label="Pipeline stages">
            {PIPELINE.map((s, i) => (
              <li key={s.n} className="pipe-stage">
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
                {i < PIPELINE.length - 1 && (
                  <span className="pipe-arrow" aria-hidden="true">
                    <svg width="16" height="12" viewBox="0 0 16 12">
                      <path d="M0 6h13M9 1l5 5-5 5" fill="none" stroke="currentColor" strokeWidth="1.5" />
                    </svg>
                  </span>
                )}
              </li>
            ))}
          </ol>
        </section>

        <section className="about-sec" aria-labelledby="ab-q">
          <h2 id="ab-q">The research question, in one sentence</h2>
          <p className="about-question">{STUDY_QUESTION}</p>
          <p className="about-small">
            Data: the <Term id="ait-ads">AIT-ADS</Term> alert dataset. The <Term id="agent">investigation agent</Term> and the <Term id="multi-agent">multi-agent graph</Term> run on the same cases under a{' '}
            <Term id="matched-budget">matched budget</Term>; each <Term id="detector">alert source</Term> is compared with <Term id="baseline">baselines</Term> and with the <Term id="oracle">oracle</Term>,{' '}
            <Term id="noise">noise</Term> and <Term id="shuffled">shuffled</Term> controls. Headline: <Term id="coverage">coverage</Term> of <Term id="reachable-phase">alert-reachable phases</Term> after the{' '}
            <Term id="verifier">evidence verifier</Term>.
          </p>
        </section>

        <section className="about-sec" aria-labelledby="ab-results">
          <h2 id="ab-results">Results so far</h2>
          <ResultsStatus allowed={mayReadStudy} data={study.data} loading={study.loading} error={study.error} reload={study.reload} />
        </section>

        <section className="about-sec" aria-labelledby="ab-screens">
          <h2 id="ab-screens">What each screen shows, and why</h2>
          <ul className="screen-guide">
            {screens.map((g) => (
              <li key={g.path}>
                <a href={`#${g.path}`} className="screen-card">
                  <span className="screen-card-name">
                    {g.name} <Icon name="chevronRight" />
                  </span>
                  <span>{g.what}</span>
                  <span className="faint">{g.why}</span>
                </a>
              </li>
            ))}
          </ul>
        </section>

        <section className="about-sec" aria-labelledby="ab-limits">
          <h2 id="ab-limits">Limits and honesty notes</h2>
          <ul className="limits">
            {LIMITS.map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
        </section>

        <section className="about-sec" aria-labelledby="ab-gloss">
          <h2 id="ab-gloss">Glossary</h2>
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
        </section>
      </div>
    </div>
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
        <div className="v num">{fmtInt(data.incomplete_runs)} run{data.incomplete_runs === 1 ? '' : 's'} without scores yet</div>
        <div className="s">{data.excluded_fake_runs ? `${fmtInt(data.excluded_fake_runs)} plumbing-check runs (fake model) not counted.` : 'Runs with a fake model are never counted.'}</div>
      </div>
      <p className="about-small rs-note">
        {pilot.length || final.length ? (
          <>
            The numbers themselves are on the <a href="#/study">Study page</a>, read from the run files; nothing here is typed in.
          </>
        ) : (
          <>
            When a run finishes, the <a href="#/study">Study page</a> will show, per alert source and arm: coverage of the reachable attack phases, citation precision, and the unsupported-claim rate before and after the verifier, next to the baselines. Until then it is empty on purpose.
          </>
        )}
      </p>
    </div>
  );
}
