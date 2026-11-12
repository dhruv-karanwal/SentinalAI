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
  overview: <path d="M2.5 13.5V8M6.2 13.5V4.5M9.8 13.5V9.5M13.5 13.5V2.5" />,
  study: <path d="M2.5 13.5h11M4 11V7.5M7 11V4M10 11V6M13 11V9" />,
  users: <path d="M6 2.8a2.3 2.3 0 1 1 0 4.6 2.3 2.3 0 0 1 0-4.6ZM1.8 13.2c.4-2.2 2-3.3 4.2-3.3s3.8 1.1 4.2 3.3M10.5 3a2.1 2.1 0 0 1 0 4.1M12 9.9c1.2.4 1.9 1.4 2.2 3.1" />,
  settings: <path d="M8 5.6a2.4 2.4 0 1 1 0 4.8 2.4 2.4 0 0 1 0-4.8ZM8 1.8v2M8 12.2v2M1.8 8h2M12.2 8h2M3.6 3.6 5 5M11 11l1.4 1.4M3.6 12.4 5 11M11 5l1.4-1.4" />,
  help: <path d="M8 2a6 6 0 1 1 0 12A6 6 0 0 1 8 2ZM6.3 6.3a1.8 1.8 0 1 1 2.4 1.7c-.5.2-.7.5-.7 1.1M8 11.3v.1" />,
  bell: <path d="M4 11.5V7.2a4 4 0 0 1 8 0v4.3l1.2 1.3H2.8L4 11.5ZM6.6 14.2a1.5 1.5 0 0 0 2.8 0" />,
  executive: <path d="M2.5 4.5h11v9h-11zM5.8 4.5V2.8h4.4v1.7M2.5 8.5h11" />,
  graph: <path d="M4 4.5a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3ZM12 8.5a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3ZM5 14.5a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3ZM5.3 3.7l5.3 2.6M10.7 8l-4.6 4.2" />,
  filter: <path d="M2 3h12L9.5 8.5v4.5l-3 1.3V8.5z" />,
  print: <path d="M4.5 6V2h7v4M4.5 11.5h-2V6h11v5.5h-2M4.5 9.5h7v4.5h-7z" />,
  entity: <path d="M2.5 3.5h11v6h-11zM5.5 12.5h5M8 9.5v3" />,
  signOut: <path d="M6.5 2.5h-4v11h4M10 5l3 3-3 3M13 8H6" />,
  about: <path d="M8 2a6 6 0 1 1 0 12A6 6 0 0 1 8 2ZM8 7.2v4.3M8 4.8v.1" />,
  play: <path d="M5 3.2v9.6L12.5 8 5 3.2Z" />,
  chat: <path d="M2.5 3h11v7.5H6.5L3.5 13.2v-2.7h-1zM5 6.8h6" />,
  send: <path d="M2.5 8 13.5 2.8 10 13.2 7.6 8.6 2.5 8ZM7.6 8.6l5.9-5.8" />,
  minimise: <path d="M3.5 11.5h9" />,
  expand: <path d="M9.5 2.5h4v4M13.5 2.5 9 7M6.5 13.5h-4v-4M2.5 13.5 7 9" />,
  trash: <path d="M2.5 4.5h11M6 4.5V2.8h4v1.7M4 4.5l.7 9h6.6l.7-9" />,
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

/**
 * Brand mark (original): a shield outline with three signal arcs rising from a point inside it.
 * One colour (currentColor); legible at 16, 24 and 40 px.
 */
export function BrandMark({ size = 20, label }: { size?: number; label?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" role={label ? 'img' : undefined} aria-label={label} aria-hidden={label ? undefined : true} focusable="false">
      <path d="M12 2.5 4 5.5v6c0 4.9 3.4 8.6 8 10 4.6-1.4 8-5.1 8-10v-6l-8-3Z" />
      <path d="M9.2 12.6a4 4 0 0 1 5.6 0M7.2 10.4a6.8 6.8 0 0 1 9.6 0" />
      <circle cx="12" cy="15.2" r="1.2" fill="currentColor" stroke="none" />
    </svg>
  );
}

/** The brand mark as an SVG data URL for the favicon (the accent colour of the dark theme is not used: the tab bar has its own background, so a neutral stroke). */
export const FAVICON_SVG = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M12 2.5 4 5.5v6c0 4.9 3.4 8.6 8 10 4.6-1.4 8-5.1 8-10v-6l-8-3Z'/><path d='M9.2 12.6a4 4 0 0 1 5.6 0M7.2 10.4a6.8 6.8 0 0 1 9.6 0'/><circle cx='12' cy='15.2' r='1.4' fill='%23' stroke='none'/></svg>";
