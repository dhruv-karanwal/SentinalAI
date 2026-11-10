// Fixed-row-height windowing: only the visible rows (plus overscan) are rendered.

export interface VisibleRange {
  /** first rendered row index (inclusive) */
  start: number;
  /** last rendered row index (exclusive) */
  end: number;
  /** pixel offset of the first rendered row from the top of the list */
  offset: number;
  /** total list height in pixels */
  total: number;
}

export function visibleRange(
  scrollTop: number,
  viewportHeight: number,
  rowHeight: number,
  count: number,
  overscan = 8,
): VisibleRange {
  const total = count * rowHeight;
  if (count <= 0 || rowHeight <= 0 || viewportHeight <= 0) return { start: 0, end: 0, offset: 0, total: Math.max(0, total) };
  const top = Math.min(Math.max(0, scrollTop), Math.max(0, total - viewportHeight));
  const first = Math.floor(top / rowHeight);
  const visible = Math.ceil(viewportHeight / rowHeight) + 1;
  const start = Math.max(0, first - overscan);
  const end = Math.min(count, first + visible + overscan);
  return { start, end, offset: start * rowHeight, total };
}

/** The scrollTop that brings row `index` fully into view, changing nothing when it already is. */
export function scrollTopFor(index: number, scrollTop: number, viewportHeight: number, rowHeight: number): number {
  const rowTop = index * rowHeight;
  const rowBottom = rowTop + rowHeight;
  if (rowTop < scrollTop) return rowTop;
  if (rowBottom > scrollTop + viewportHeight) return rowBottom - viewportHeight;
  return scrollTop;
}

export function clampIndex(index: number, count: number): number {
  if (count <= 0) return -1;
  return Math.min(count - 1, Math.max(0, index));
}
