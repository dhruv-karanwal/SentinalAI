// Settings (per viewer, localStorage): theme, row density, time format, default data source.
// Also the Security notes page (docs/security-notes.md shown as plain text).

import securityNotes from '../../../docs/security-notes.md?raw';
import { storageGet, storageSet, type TimeFormat } from '../hooks.ts';

interface Props {
  theme: 'dark' | 'light';
  density: 'compact' | 'comfortable';
  timeFormat: TimeFormat;
  scenarios: string[];
  onTheme: (t: 'dark' | 'light') => void;
  onDensity: (d: 'compact' | 'comfortable') => void;
  onTimeFormat: (f: TimeFormat) => void;
  demo: boolean;
  onDemo: (on: boolean) => void;
}

function Choice<T extends string>({ name, legend, value, options, onChange, hint }: { name: string; legend: string; value: T; options: Array<[T, string]>; onChange: (v: T) => void; hint: string }) {
  return (
    <fieldset className="section" style={{ border: 0, margin: 0 }}>
      <legend className="section-title">{legend}</legend>
      <div style={{ display: 'flex', gap: 'var(--sp-16)', flexWrap: 'wrap' }}>
        {options.map(([v, label]) => (
          <label key={v} style={{ display: 'inline-flex', gap: 'var(--sp-4)', alignItems: 'center' }}>
            <input type="radio" name={name} value={v} checked={value === v} onChange={() => onChange(v)} />
            {label}
          </label>
        ))}
      </div>
      <p className="faint" style={{ margin: 'var(--sp-4) 0 0', fontSize: 'var(--fs-12)' }}>
        {hint}
      </p>
    </fieldset>
  );
}

export function SettingsScreen({ theme, density, timeFormat, scenarios, onTheme, onDensity, onTimeFormat, demo, onDemo }: Props) {
  const def = storageGet('sentinel.defaultScenario') ?? '';
  return (
    <div className="page">
      <div className="page-head">
        <h1>Settings</h1>
        <span className="faint">Stored in this browser only; nothing is sent to the API.</span>
      </div>
      <div className="page-body" style={{ maxWidth: 720 }}>
        <div className="chart">
          <Choice
            name="demo"
            legend="Professor demo mode"
            value={demo ? 'on' : 'off'}
            options={[['on', 'On: start on "How SentinelAI works"'], ['off', 'Off: start on the home screen of your role']]}
            onChange={(v) => onDemo(v === 'on')}
            hint="For a first-time reader. Remembered in this browser. The tour and the Explain chat work in both modes."
          />
          <Choice name="theme" legend="Theme" value={theme} options={[['dark', 'Dark'], ['light', 'Light']]} onChange={onTheme} hint="Shortcut: t. Printing always uses the light theme." />
          <Choice
            name="density"
            legend="Row density"
            value={density}
            options={[['compact', 'Compact (24 px rows)'], ['comfortable', 'Comfortable (32 px rows)']]}
            onChange={onDensity}
            hint="Shortcut: d."
          />
          <Choice
            name="timefmt"
            legend="Time format"
            value={timeFormat}
            options={[['iso', 'ISO 8601 (2022-01-21T00:02:27Z)'], ['short', 'Short (2022-01-21 00:02:27)']]}
            onChange={onTimeFormat}
            hint="All times are UTC; the relative time is in the hover text."
          />
          <div className="section">
            <label className="section-title" htmlFor="def-sc">
              Default data source
            </label>
            <select id="def-sc" className="select mono" defaultValue={def} onChange={(e) => storageSet('sentinel.defaultScenario', e.target.value)}>
              <option value="">first stored scenario</option>
              {scenarios.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <p className="faint" style={{ margin: 'var(--sp-4) 0 0', fontSize: 'var(--fs-12)' }}>
              Used after sign-in when no data source was chosen in this browser yet.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export function SecurityNotes() {
  return (
    <div className="page">
      <div className="page-head">
        <h1>Security notes</h1>
        <span className="faint mono">docs/security-notes.md</span>
      </div>
      <div className="page-body">
        <pre className="raw" style={{ whiteSpace: 'pre-wrap', maxWidth: 960 }}>
          {securityNotes}
        </pre>
      </div>
    </div>
  );
}
