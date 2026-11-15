// Phone width: list and detail stack (work.css) and tables drop their secondary columns, so the
// fixed tracks still fit a 390 px pane without a horizontal scroll inside the row.

import { useSyncExternalStore } from 'react';

const QUERY = '(max-width: 700px)';

function subscribe(onChange: () => void): () => void {
  const m = window.matchMedia(QUERY);
  m.addEventListener('change', onChange);
  return () => m.removeEventListener('change', onChange);
}

export function useNarrow(): boolean {
  return useSyncExternalStore(subscribe, () => window.matchMedia(QUERY).matches);
}

/** The columns without the ids in `hide` when `narrow`. */
export function fitColumns<C extends { id: string }>(columns: readonly C[], narrow: boolean, hide: readonly string[]): C[] {
  return narrow ? columns.filter((c) => !hide.includes(c.id)) : [...columns];
}
