// The whole icon set: hand-authored, 16 px grid, one 1.5 px stroke, currentColor.
// Icons are decoration next to a text label unless `label` is given.

import type { ReactNode } from 'react';

const PATHS = {
  incidents: <path d="M8 2.2 14 13H2L8 2.2ZM8 6.5v3M8 11.2v.1" />,
  alerts: <path d="M2.5 4h11M2.5 8h11M2.5 12h7" />,
  approvals: <path d="M2.5 2.5h11v11h-11zM5 8.2l2.1 2.1L11 6" />,
  reports: <path d="M4 1.8h5.5L12.5 5v9.2H4zM9.2 1.8V5.2h3.3M6 8.5h4.5M6 11h4.5" />,
  ask: <path d="M2.5 3h11v7.5H8L5 13.2v-2.7H2.5zM6.6 5.8a1.5 1.5 0 1 1 2 1.4c-.4.2-.6.4-.6.9" />,
  audit: <path d="M8 2.5a5.5 5.5 0 1 1-5.2 3.7M2.5 2.8v3.4h3.4M8 5v3.2l2.2 1.3" />,
  search: <path d="M7 2.5a4.5 4.5 0 1 1 0 9 4.5 4.5 0 0 1 0-9ZM10.3 10.3l3.2 3.2" />,
  copy: <path d="M5.5 5.5h8v8h-8zM2.5 10.5v-8h8" />,
  check: <path d="M3 8.5l3.2 3.2L13 4.8" />,
  close: <path d="M3.5 3.5l9 9M12.5 3.5l-9 9" />,
  chevronRight: <path d="M6 3.5 10.5 8 6 12.5" />,
  chevronDown: <path d="M3.5 6 8 10.5 12.5 6" />,
  sortAsc: <path d="M8 13V3.5M4.5 7 8 3.5 11.5 7" />,
  sortDesc: <path d="M8 3v9.5M4.5 9 8 12.5 11.5 9" />,
  sun: <path d="M8 5.2a2.8 2.8 0 1 1 0 5.6 2.8 2.8 0 0 1 0-5.6ZM8 1.5v1.6M8 12.9v1.6M1.5 8h1.6M12.9 8h1.6M3.4 3.4l1.1 1.1M11.5 11.5l1.1 1.1M3.4 12.6l1.1-1.1M11.5 4.5l1.1-1.1" />,
  moon: <path d="M13 9.6A5.5 5.5 0 0 1 6.4 3 5.5 5.5 0 1 0 13 9.6Z" />,
  density: <path d="M2.5 3h11M2.5 6.3h11M2.5 9.7h11M2.5 13h11" />,
  download: <path d="M8 2.5v8M4.8 7.5 8 10.5l3.2-3M2.8 13.5h10.4" />,
  refresh: <path d="M13 8a5 5 0 1 1-1.6-3.7M13 2.5v3.2H9.8" />,
  keyboard: <path d="M1.8 4h12.4v8H1.8zM4.2 6.6h.1M6.7 6.6h.1M9.2 6.6h.1M11.7 6.6h.1M5 9.5h6" />,
  user: <path d="M8 2.5a2.6 2.6 0 1 1 0 5.2 2.6 2.6 0 0 1 0-5.2ZM3 13.5c.5-2.4 2.4-3.6 5-3.6s4.5 1.2 5 3.6" />,
  warning: <path d="M8 2.2 14 13H2L8 2.2ZM8 6.5v3M8 11.2v.1" />,
  signOut: <path d="M6.5 2.5h-4v11h4M10 5l3 3-3 3M13 8H6" />,
} satisfies Record<string, ReactNode>;

export type IconName = keyof typeof PATHS;

export function Icon({ name, label }: { name: IconName; label?: string }) {
  return (
    <svg
      className="icon"
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      role={label ? 'img' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
      focusable="false"
    >
      {PATHS[name]}
    </svg>
  );
}

/** Severity glyph: three stacked bars, 3 / 2 / 1 filled for High / Medium / Low. Always shown with the word. */
export function SeverityGlyph({ level }: { level: 0 | 1 | 2 | 3 }) {
  // bars from the bottom up: Low fills the bottom bar, Medium two, High all three
  return (
    <svg className="icon" width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      {[0, 1, 2].map((i) => {
        const filled = 3 - i <= level;
        const y = 2 + i * 4.5;
        return filled ? (
          <rect key={i} x="2" y={y} width="12" height="3" fill="currentColor" />
        ) : (
          <rect key={i} x="2.5" y={y + 0.5} width="11" height="2" fill="none" stroke="currentColor" strokeWidth="1" strokeOpacity="0.6" />
        );
      })}
    </svg>
  );
}
