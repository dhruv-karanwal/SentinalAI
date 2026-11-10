// List on the left, detail on the right, with a draggable and keyboard-operable divider.

import { useCallback, useRef, useState, type ReactNode } from 'react';

import { storageGet, storageSet } from '../hooks.ts';

const MIN = 25;
const MAX = 70;

export function SplitPane({ id, left, right, initial = 46 }: { id: string; left: ReactNode; right: ReactNode; initial?: number }) {
  const key = `sentinel.split.${id}`;
  const [pct, setPct] = useState(() => {
    const stored = Number(storageGet(key));
    return stored >= MIN && stored <= MAX ? stored : initial;
  });
  const ref = useRef<HTMLDivElement | null>(null);

  const apply = useCallback(
    (value: number) => {
      const v = Math.min(MAX, Math.max(MIN, Math.round(value)));
      setPct(v);
      storageSet(key, String(v));
    },
    [key],
  );

  const onPointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    const box = ref.current?.getBoundingClientRect();
    if (!box) return;
    e.preventDefault();
    e.currentTarget.setPointerCapture(e.pointerId);
    const move = (ev: PointerEvent) => apply(((ev.clientX - box.left) / box.width) * 100);
    const up = () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', up);
    };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowLeft') apply(pct - 2);
    else if (e.key === 'ArrowRight') apply(pct + 2);
    else if (e.key === 'Home') apply(MIN);
    else if (e.key === 'End') apply(MAX);
    else return;
    e.preventDefault();
  };

  return (
    <div ref={ref} className="split" style={{ gridTemplateColumns: `minmax(0, ${pct}fr) auto minmax(0, ${100 - pct}fr)` }}>
      <section className="pane" aria-label="List">
        {left}
      </section>
      <div
        className="divider"
        role="separator"
        aria-orientation="vertical"
        aria-label="Resize list and detail"
        aria-valuenow={pct}
        aria-valuemin={MIN}
        aria-valuemax={MAX}
        tabIndex={0}
        onPointerDown={onPointerDown}
        onKeyDown={onKeyDown}
      />
      <section className="pane" aria-label="Detail">
        {right}
      </section>
    </div>
  );
}
