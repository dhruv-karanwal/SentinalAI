// Settings (per viewer, localStorage): theme, row density, time format, default data source.
// Also the Security notes page (docs/security-notes.md shown as plain text).

import securityNotes from '../../../docs/security-notes.md?raw';
import { Page, PageHeader, Section } from '../components/ui.tsx';
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

/** One form row: label left, the radio group and its help text right. */
function Choice<T extends string>({ name, legend, value, options, onChange, hint }: { name: string; legend: string; value: T; options: Array<[T, string]>; onChange: (v: T) => void; hint: string }) {
  return (
    <div className="form-row" role="radiogroup" aria-labelledby={`set-${name}`} aria-describedby={`set-${name}-help`}>
      <span className="form-label" id={`set-${name}`}>
        {legend}
      </span>
      <div className="form-control">
        <div className="radio-row">
          {options.map(([v, label]) => (
            <label key={v}>
              <input type="radio" name={name} value={v} checked={value === v} onChange={() => onChange(v)} />
              {label}
            </label>
          ))}
        </div>
        <p className="form-help" id={`set-${name}-help`}>
          {hint}
        </p>
      </div>
    </div>
  );
}

export function SettingsScreen({ theme, density, timeFormat, scenarios, onTheme, onDensity, onTimeFormat, demo, onDemo }: Props) {
  const def = storageGet('sentinel.defaultScenario') ?? '';
  return (
    <Page label="Settings">
      <PageHeader title="Settings" purpose="How should the console look and start for you? Stored in this browser only; nothing is sent to the API." />
      <Section id="set-start" title="Start">
        <div className="form-rows">
          <Choice
            name="demo"
            legend="Professor demo mode"
            value={demo ? 'on' : 'off'}
            options={[
              ['on', 'On: start on "How SentinelAI works"'],
              ['off', 'Off: start on the home screen of your role'],
            ]}
            onChange={(v) => onDemo(v === 'on')}
            hint="For a first-time reader. Remembered in this browser. The tour and the Explain chat work in both modes."
          />
          <div className="form-row">
            <label className="form-label" htmlFor="def-sc">
              Default data source
            </label>
            <div className="form-control">
              <select id="def-sc" className="select mono" defaultValue={def} onChange={(e) => storageSet('sentinel.defaultScenario', e.target.value)} aria-describedby="def-sc-help">
                <option value="">first stored scenario</option>
                {scenarios.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
              <p className="form-help" id="def-sc-help">
                Used after sign-in when no data source was chosen in this browser yet.
              </p>
            </div>
          </div>
        </div>
      </Section>
      <Section id="set-display" title="Display">
        <div className="form-rows">
          <Choice
            name="theme"
            legend="Theme"
            value={theme}
            options={[
              ['dark', 'Dark'],
              ['light', 'Light'],
            ]}
            onChange={onTheme}
            hint="Shortcut: t. Printing always uses the light theme."
          />
          <Choice
            name="density"
            legend="Row density"
            value={density}
            options={[
              ['compact', 'Compact (28 px rows)'],
              ['comfortable', 'Comfortable (36 px rows)'],
            ]}
            onChange={onDensity}
            hint="Shortcut: d."
          />
          <Choice
            name="timefmt"
            legend="Time format"
            value={timeFormat}
            options={[
              ['iso', 'ISO 8601 (2022-01-21T00:02:27Z)'],
              ['short', 'Short (2022-01-21 00:02:27)'],
            ]}
            onChange={onTimeFormat}
            hint="All times are UTC; the relative time is in the hover text."
          />
        </div>
      </Section>
    </Page>
  );
}

export function SecurityNotes() {
  return (
    <Page label="Security notes">
      <PageHeader title="Security notes" purpose="How is the console protected, and what does it never do?" crumbs={[{ label: 'Settings', href: '#/settings' }, { label: 'Security notes' }]} />
      <Section title="docs/security-notes.md" description="The document as committed, shown as plain text.">
        <div className="card">
          <pre className="security-text">{securityNotes}</pre>
        </div>
      </Section>
    </Page>
  );
}
