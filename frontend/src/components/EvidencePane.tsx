// The evidence for one alert: its raw log lines first (the matched span marked), then its fields,
// then the stored JSON behind a disclosure. Everything here is untrusted text and is rendered as
// text nodes only.

import { useEffect, useRef } from 'react';

import { api, can } from '../api.ts';
import { useApp, useLoad } from '../hooks.ts';
import { Icon } from '../icons.tsx';
import { CopyButton, DetectorTag, Disclosure, ErrorState, Id, SkeletonLines, Time, TruncatedText } from './ui.tsx';

const SEVERITY_SCALE: Record<string, string> = {
  wazuh: 'Wazuh rule level, 0-15, higher is more severe',
  suricata: 'Suricata severity, 1 is most severe',
};

export function EvidencePane({
  alertId,
  needles = [],
  onClose,
  focusKey,
}: {
  alertId: string;
  needles?: readonly string[];
  onClose?: () => void;
  /** when this value changes, focus moves to the pane (opened from a citation or with Enter) */
  focusKey?: string | number | null;
}) {
  const { session } = useApp();
  const allowed = can(session.role, 'read.raw');
  const { data, error, loading, reload } = useLoad((signal) => (allowed ? api.alert(alertId, signal) : Promise.resolve(null)), [alertId, allowed]);
  const headRef = useRef<HTMLHeadingElement | null>(null);
  useEffect(() => {
    if (focusKey != null) headRef.current?.focus();
  }, [focusKey]);

  const rec = data?.record;
  const lines = rec?.evidence?.log_lines ?? [];
  const paths = rec?.evidence?.log_paths ?? [];
  const hits = needles.length > 0 ? lines.filter((l) => needles.some((n) => l.toLowerCase().includes(n.toLowerCase()))).length : 0;

  return (
    <div className="ev" role="region" aria-label={`Evidence for alert ${alertId}`}>
      <div className="pane-bar ev-head">
        <h2 ref={headRef} tabIndex={-1}>
          Evidence
        </h2>
        <Id value={alertId} label="Copy alert id" />
        <span className="spacer" />
        {onClose && (
          <button type="button" className="btn ghost" onClick={onClose} title="Close (Esc)">
            <Icon name="close" />
            Close
          </button>
        )}
      </div>
      <div className="detail-scroll">
        {!allowed ? (
          <div className="state" data-kind="error" role="alert">
            <div className="state-title">
              <Icon name="warning" />
              Not permitted
            </div>
            <p>Your role ({session.role}) cannot read raw alert records.</p>
          </div>
        ) : error && !data ? (
          <ErrorState what={`alert ${alertId}`} error={error} onRetry={reload} />
        ) : loading && !data ? (
          <SkeletonLines lines={6} />
        ) : data ? (
          <>
            <section className="block" aria-labelledby={`ev-lines-${alertId}`}>
              <h3 className="block-title" id={`ev-lines-${alertId}`}>
                Log lines <span className="meta num">{lines.length}</span>
                {needles.length > 0 && (
                  <span className="meta">{hits > 0 ? `match in ${hits} of ${lines.length}` : 'no match for the highlighted text in these lines'}</span>
                )}
              </h3>
              {lines.length === 0 ? (
                <p className="muted">
                  This alert carries no log line{data.kind === 'aggregate' ? ' (aggregate alerts summarise a window)' : ''}. The raw alert is
                  below.
                </p>
              ) : (
                <div className="ev-lines">
                  {lines.map((line, i) => (
                    <div className="ev-line" key={i}>
                      <span className="n">{i + 1}</span>
                      <span className="text">
                        <TruncatedText text={line} needles={needles} />
                      </span>
                      <CopyButton text={line} label={`Copy log line ${i + 1}`} />
                    </div>
                  ))}
                </div>
              )}
            </section>
            <section className="block" aria-label="Alert fields">
              <dl className="kv">
                <dt>Time (UTC)</dt>
                <dd>
                  <Time ts={data.ts} />
                </dd>
                <dt>Detector</dt>
                <dd>
                  <DetectorTag value={data.detector} />{' '}
                  <span className="faint">
                    {data.detector_type.replace('_', '-')}, {data.kind}
                  </span>
                </dd>
                <dt>Rule</dt>
                <dd>
                  <span className="mono">{data.rule_id ?? '-'}</span> {data.rule_name}
                </dd>
                <dt>Severity</dt>
                <dd>
                  {data.severity === null ? (
                    <span className="faint">none reported by this detector</span>
                  ) : (
                    <>
                      <span className="mono num">{data.severity}</span>{' '}
                      <span className="faint">({SEVERITY_SCALE[data.detector] ?? 'detector-native scale'})</span>
                    </>
                  )}
                </dd>
                <dt>Host</dt>
                <dd>{data.host_ip ? <Id value={data.host_ip} label="Copy host IP" /> : <span className="faint">-</span>}</dd>
                <dt>Log file</dt>
                <dd className="mono">{paths.length ? paths.join(', ') : <span className="faint">-</span>}</dd>
              </dl>
            </section>
            <section className="block" aria-label="Raw alert">
              <Disclosure summary="Raw alert (JSON as stored)">
                <pre className="ev-raw">{JSON.stringify(rec?.raw_alert ?? rec ?? {}, null, 2)}</pre>
              </Disclosure>
            </section>
          </>
        ) : null}
      </div>
    </div>
  );
}
