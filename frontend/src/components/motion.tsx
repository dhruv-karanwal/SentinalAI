// Motion primitives (DESIGN.md 6): scroll reveal and chart draw-in on first view, each once. IntersectionObserver + requestAnimationFrame only; every one shows the final state
// at once under prefers-reduced-motion.

import { useEffect, useRef, useState, type RefObject } from 'react';

import { prefersReducedMotion } from '../lib/motion.ts';

/** True once the element has been on screen (fires once, then disconnects). */
export function useSeen<T extends Element>(ref: RefObject<T | null>, rootMargin = '0px 0px -10% 0px'): boolean {
  const [seen, setSeen] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el || seen) return;
    if (prefersReducedMotion() || typeof IntersectionObserver === 'undefined') {
      setSeen(true);
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setSeen(true);
          io.disconnect();
        }
      },
      { rootMargin },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [ref, rootMargin, seen]);
  return seen;
}

/** Wrapper that fades/slides its children in the first time they scroll into view. */
export function Reveal({ children, i = 0, as: Tag = 'div', className, id, sev, ...rest }: { children: React.ReactNode; i?: number; as?: 'div' | 'section' | 'li'; className?: string; id?: string; sev?: string; 'aria-labelledby'?: string }) {
  const ref = useRef<HTMLElement | null>(null);
  const seen = useSeen(ref);
  return (
    <Tag
      ref={ref as never}
      id={id}
      className={className}
      data-reveal=""
      data-sev={sev}
      data-shown={seen ? '' : undefined}
      style={{ '--i': i } as React.CSSProperties}
      {...rest}
    >
      {children}
    </Tag>
  );
}

/** data-drawn="0" until first seen, then "1": dash.css grows bars and fades lines in once. */
export function DrawOnView({ children, className }: { children: React.ReactNode; className?: string }) {
  const ref = useRef<HTMLDivElement | null>(null);
  const seen = useSeen(ref);
  return (
    <div ref={ref} className={className} data-drawn={seen ? '1' : '0'}>
      {children}
    </div>
  );
}
