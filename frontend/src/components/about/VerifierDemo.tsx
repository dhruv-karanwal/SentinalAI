// The verifier on a labelled SAMPLE line with the real quote rule (exact, case-sensitive substring,
// at least 8 characters: quoteSupported in content/about.ts). The two sample claims resolve once
// when seen (short stagger); "Run the check again" replays; the reader can try their own quote.

import { useRef, useState } from 'react';

import { VERIFIER_SAMPLE, quoteSupported } from '../../content/about.ts';
import { Icon } from '../../icons.tsx';
import { useSeen } from '../motion.tsx';
import { Button } from '../ui.tsx';

function Verdict({ kept, reason }: { kept: boolean; reason: string }) {
  return (
    <span className="ab-verdict" data-v={kept ? 'kept' : 'dropped'}>
      <Icon name={kept ? 'check' : 'close'} />
      {reason}
    </span>
  );
}

export function VerifierDemo() {
  const ref = useRef<HTMLDivElement | null>(null);
  const seen = useSeen(ref);
  const [run, setRun] = useState(0);
  const [own, setOwn] = useState('');
  const ownResult = own ? quoteSupported(VERIFIER_SAMPLE.line, own) : null;
  return (
    <div className="ab-verify" ref={ref}>
      <div className="ab-evidence">
        <div className="ab-col-label">
          Evidence: the cited log line <span className="ab-tag">Sample</span>
        </div>
        <p className="ab-logline mono">{VERIFIER_SAMPLE.line}</p>
        <p className="ab-cap faint">Synthetic line (a documentation address, a made-up path), not from a run.</p>
        <Button icon="refresh" onClick={() => setRun((r) => r + 1)}>
          Run the check again
        </Button>
      </div>

      <div className="ab-claims">
        <ul className="ab-claim-list" key={run}>
          {VERIFIER_SAMPLE.claims.map((c, i) => {
            const r = quoteSupported(VERIFIER_SAMPLE.line, c.quote);
            return (
              <li key={c.quote} className="ab-claim" data-v={seen ? (r.kept ? 'kept' : 'dropped') : undefined}>
                <span className="ab-claim-text">{c.text}</span>
                <span className="ab-claim-quote mono">quote: "{c.quote}"</span>
                {seen && (
                  <span className="ab-claim-result" style={{ '--i': i * 6 } as React.CSSProperties}>
                    <Verdict {...r} />
                  </span>
                )}
              </li>
            );
          })}
        </ul>

        <div className="ab-try">
          <label className="ab-col-label" htmlFor="ab-own">
            Try your own quote against the line
          </label>
          <input id="ab-own" className="input mono" value={own} maxLength={120} onChange={(e) => setOwn(e.target.value)} placeholder="e.g. POST /wp-login.php" autoComplete="off" spellCheck={false} />
          <div role="status" className="ab-try-result">
            {ownResult ? <Verdict {...ownResult} /> : <span className="faint">Type at least 8 characters copied exactly from the line to keep a quote.</span>}
          </div>
        </div>
      </div>
    </div>
  );
}
