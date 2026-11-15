// About (DESIGN.md 7): the product page, and the landing page in Professor demo mode. Sections in
// order, with a sticky section nav that follows the scroll position: hero (one sentence, one line,
// a live mini-view of the product), how it works (the pipeline flow, plays once), the study
// (interactive diagram), the verifier demo (labelled SAMPLE), features by category, the honest
// results status and limits, the glossary. Every number comes from the API.

import { useEffect, useMemo, useRef, useState } from 'react';

import { api, can, type ApiError, type StudyResults } from '../api.ts';
import { MiniView } from '../components/about/MiniView.tsx';
import { PipelineFlow } from '../components/about/PipelineFlow.tsx';
import { StudyDiagram } from '../components/about/StudyDiagram.tsx';
import { VerifierDemo } from '../components/about/VerifierDemo.tsx';
import { Reveal } from '../components/motion.tsx';
import { Term } from '../components/Term.tsx';
import { Button, ErrorNotice, Kpi, Section, SkeletonLines } from '../components/ui.tsx';
import { FEATURES, LIMITS, PROBLEM } from '../content/about.ts';
import { GLOSSARY } from '../content/glossary.ts';
import { useApp, useLoad, useScreenContext } from '../hooks.ts';
import { Icon } from '../icons.tsx';
import { searchGlossary } from '../lib/explain.ts';
import { fmtInt } from '../lib/format.ts';
import { activeSection, prefersReducedMotion } from '../lib/motion.ts';

const SECTIONS = [
  ['ab-hero', 'Start'],
  ['ab-how', 'How it works'],
  ['ab-study', 'The study'],
  ['ab-verify', 'The verifier'],
  ['ab-features', 'Features'],
  ['ab-status', 'Status and limits'],
  ['ab-gloss', 'Glossary'],
] as const;

export function AboutScreen({ onTour }: { onTour: () => void }) {
  const { session, scenario } = useApp();
  const mayReadStudy = can(session.role, 'read.raw');
  const study = useLoad((signal) => (mayReadStudy ? api.study(signal) : Promise.resolve(null)), [mayReadStudy]);
  const overview = useLoad((signal) => (scenario ? api.overview(scenario, signal) : Promise.resolve(null)), [scenario]);
  const incidents = useLoad((signal) => (scenario ? api.incidentSummaries(scenario, signal).then((r) => r.incidents) : Promise.resolve(null)), [scenario]);
  const scroller = useRef<HTMLDivElement | null>(null);
  const [current, setCurrent] = useState(0);

  const o = overview.data;
  useScreenContext(
    'about',
    `About SentinelAI: what the system is and how far the study has got. Sections: ${SECTIONS.map(([, n]) => n).join(', ')}.${
      o ? ` Live view of data source ${o.scenario}: ${o.alerts} stored alerts, ${o.status.incidents} incidents, ${o.detectors.filter((d) => d.alerts > 0).length} detectors with alerts.` : ''
    }`,
  );

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

  const features = FEATURES.map((g) => ({ ...g, items: g.items.filter((f) => !f.permission || can(session.role, f.permission)) })).filter((g) => g.items.length > 0);

  return (
    <div className="page about" ref={scroller}>
      <div className="ab-wrap">
        <nav className="ab-nav" aria-label="Sections of this page">
          <ol>
            {SECTIONS.map(([id, name], i) => (
              <li key={id}>
                <a
                  href="#/about"
                  aria-current={i === current ? 'true' : undefined}
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

        <div className="ab-main">
          <section className="ab-hero" id="ab-hero" aria-labelledby="ab-hero-t">
            <div className="ab-hero-text">
              <h1 id="ab-hero-t">From raw alerts to a checked, human-approved answer.</h1>
              <p className="ab-lead">
                SentinelAI replays the <Term id="ait-ads">AIT-ADS</Term> alerts through a security-operations pipeline, lets a local AI investigate with citations, and checks every citation before a
                person acts.
              </p>
              <div className="ab-actions">
                <Button kind="primary" className="lg" icon="play" onClick={onTour}>
                  Take the tour
                </Button>
                <a className="btn lg" href="#/overview">
                  Open the overview
                </a>
              </div>
            </div>
            <div className="ab-hero-view">
              <MiniView scenario={scenario} overview={o} overviewError={overview.error} incidents={incidents.data} />
            </div>
          </section>

          <Reveal>
            <Section id="ab-how" title="How it works" description="Five stages, each a real part of the code. Select a stage to open it.">
              <p className="ab-body">{PROBLEM}</p>
              <PipelineFlow overview={o} />
            </Section>
          </Reveal>

          <Reveal>
            <Section id="ab-study" title="The study: same investigator, different alerts" description="Switch the alert source and follow it through the fixed agent to the four arms.">
              <StudyDiagram overview={o} />
            </Section>
          </Reveal>

          <Reveal>
            <Section
              id="ab-verify"
              title="Every claim is checked against the evidence"
              description="A quote is kept only if it is an exact, case-sensitive part of a cited log line, at least 8 characters long; every drop is counted."
            >
              <VerifierDemo />
            </Section>
          </Reveal>

          <Reveal>
            <Section id="ab-features" title="What the console does" description="Each feature opens the screen it lives on.">
              <div className="grid-12 ab-features">
                {features.map((g) => (
                  <article key={g.id} className="card col-3 ab-feature" aria-labelledby={`ab-f-${g.id}`}>
                    <h3 id={`ab-f-${g.id}`}>{g.name}</h3>
                    <p className="faint">{g.summary}</p>
                    <ul>
                      {g.items.map((f) => (
                        <li key={f.screen}>
                          <a href={`#${f.path}`}>{f.screen}</a>
                          <span>{f.text}</span>
                        </li>
                      ))}
                    </ul>
                  </article>
                ))}
              </div>
            </Section>
          </Reveal>

          <Reveal>
            <Section id="ab-status" title="Where the study stands" description="Live from the result files; the numbers themselves are only on the Study page.">
              <ResultsStatus allowed={mayReadStudy} data={study.data} loading={study.loading} error={study.error} reload={study.reload} />
              <h3 className="ab-sub">Limits and honesty notes</h3>
              <ul className="ab-limits">
                {LIMITS.map((l) => (
                  <li key={l}>{l}</li>
                ))}
              </ul>
            </Section>
          </Reveal>

          <Glossary />
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
    <Reveal>
      <Section
        id="ab-gloss"
        title="Every term, in plain words"
        description="The same glossary behind every “?” in the console."
        actions={
          <div className="ab-search">
            <Icon name="search" />
            <label className="visually-hidden" htmlFor="gl-q">
              Filter the glossary
            </label>
            <input id="gl-q" className="input" placeholder={`Filter ${GLOSSARY.length} terms`} value={q} maxLength={80} onChange={(e) => setQ(e.target.value)} />
          </div>
        }
      >
        {terms.length === 0 ? (
          <p className="faint">No term matches "{q}".</p>
        ) : (
          <dl className="ab-glossary">
            {terms.map((t) => (
              <div key={t.id} className="ab-gl-row" id={`gl-${t.id}`}>
                <dt>{t.term}</dt>
                <dd>
                  <span>{t.definition}</span>
                  <span className="faint">Why it matters here: {t.why}</span>
                  {t.see && (
                    <a href={`#${t.see}`}>
                      Open the screen
                    </a>
                  )}
                </dd>
              </div>
            ))}
          </dl>
        )}
      </Section>
    </Reveal>
  );
}

function ResultsStatus({ allowed, data, loading, error, reload }: { allowed: boolean; data: StudyResults | null; loading: boolean; error: ApiError | null; reload: () => void }) {
  if (!allowed) return <p className="faint">Your role cannot read study results; the Study page is for analysts, managers and admins.</p>;
  if (error && !data) return <ErrorNotice what="study results" error={error} onRetry={reload} />;
  if (!data) return loading ? <SkeletonLines lines={2} /> : null;
  const part = (r: StudyResults['runs'][number]) => r.study_part ?? (r.split === 'held-out' ? 'held-out' : 'pilot');
  const pilot = data.runs.filter((r) => part(r) === 'pilot');
  const final = data.runs.filter((r) => part(r) === 'held-out');
  const runs = (n: number) => `${fmtInt(n)} finished run${n === 1 ? '' : 's'}`;
  return (
    <div className="ab-status">
      <div className="kpi-row">
        <Kpi
          label={
            <>
              <Term id="pilot">Pilot</Term> (dev scenarios)
            </>
          }
          value={pilot.length ? runs(pilot.length) : 'None finished yet'}
          hint="Pilot numbers, not paper results."
        />
        <Kpi
          label={
            <>
              Final (<Term id="held-out">held-out scenarios</Term>)
            </>
          }
          value={final.length ? runs(final.length) : 'Not started'}
          hint="Only after the protocol is frozen."
        />
        <Kpi
          label="In progress"
          value={`${fmtInt(data.incomplete_runs)} run${data.incomplete_runs === 1 ? '' : 's'} without scores yet`}
          hint={data.excluded_fake_runs ? `${fmtInt(data.excluded_fake_runs)} plumbing-check run${data.excluded_fake_runs === 1 ? '' : 's'} (fake model) not counted.` : 'Runs with a fake model are never counted.'}
        />
      </div>
      <p className="ab-body">
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
