// Dense table with a sticky header, fixed column tracks, sorting, keyboard selection and
// fixed-row-height windowing: only the visible rows are in the DOM, whatever the row count.

import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode } from 'react';

import { useApp, useElementSize, useNav, type NavCommand } from '../hooks.ts';
import { Icon } from '../icons.tsx';
import { fmtInt, sortBy, type SortDir } from '../lib/format.ts';
import { clampIndex, scrollTopFor, visibleRange } from '../lib/virtual.ts';

export interface Column<T> {
  id: string;
  header: string;
  /** a CSS grid track: "88px", "minmax(80px, 1fr)" */
  width: string;
  align?: 'right';
  /** makes the column sortable */
  sortKey?: (row: T) => string | number | null | undefined;
  render: (row: T) => ReactNode;
  /** plain-text value for the cell's hover text (truncated cells) */
  title?: (row: T) => string;
}

export interface DataTableProps<T> {
  label: string;
  rows: readonly T[];
  columns: readonly Column<T>[];
  rowKey: (row: T) => string;
  selectedKey?: string | null;
  onSelect?: (row: T) => void;
  /** Enter or double click */
  onOpen?: (row: T) => void;
  /** text copied by the `c` shortcut for the selected row */
  copyText?: (row: T) => string;
  /** the screen's main table: receives j / k / Enter / c from anywhere */
  primary?: boolean;
  loading?: boolean;
  empty?: ReactNode;
  footer?: ReactNode;
  initialSort?: { id: string; dir: SortDir };
  /** called when the last rows come into view (paged lists) */
  onEndReached?: () => void;
  /** a unit for the footer count: "incidents", "alerts" */
  unit?: string;
}

/** "requests" -> "request" for a count of one ("alerts loaded" -> "alert loaded"). */
function unitText(unit: string, count: number): string {
  if (count !== 1) return unit;
  const space = unit.indexOf(' ');
  const word = space < 0 ? unit : unit.slice(0, space);
  const rest = space < 0 ? '' : unit.slice(space);
  const one = word.endsWith('ies') ? `${word.slice(0, -3)}y` : word.endsWith('s') ? word.slice(0, -1) : word;
  return one + rest;
}

export function DataTable<T>(props: DataTableProps<T>) {
  const { rows, columns, rowKey, selectedKey, onSelect, onOpen, loading, primary } = props;
  const { rowHeight, toast } = useApp();
  const gridId = useId();
  const [sort, setSort] = useState<{ id: string; dir: SortDir } | null>(props.initialSort ?? null);
  const [bodyRef, size] = useElementSize<HTMLDivElement>();
  const [scrollTop, setScrollTop] = useState(0);
  const wrapRef = useRef<HTMLDivElement | null>(null);

  const sorted = useMemo(() => {
    if (!sort) return rows;
    const col = columns.find((c) => c.id === sort.id);
    return col?.sortKey ? sortBy(rows, col.sortKey, sort.dir) : rows;
  }, [rows, columns, sort]);

  const selectedIndex = useMemo(
    () => (selectedKey == null ? -1 : sorted.findIndex((r) => rowKey(r) === selectedKey)),
    [sorted, selectedKey, rowKey],
  );

  const range = visibleRange(scrollTop, size.height, rowHeight, sorted.length);
  const cols = columns.map((c) => c.width).join(' ');
  const style = { '--dt-cols': cols } as CSSProperties;

  // keep the selected row in view when the selection moves (keyboard) or the order changes
  const lastScrolledKey = useRef<string | null>(null);
  useLayoutEffect(() => {
    const el = bodyRef.current;
    if (!el || selectedIndex < 0 || size.height <= 0) return;
    const key = `${selectedKey}|${sort?.id}|${sort?.dir}|${rowHeight}|${Math.round(size.height)}`;
    if (lastScrolledKey.current === key) return;
    lastScrolledKey.current = key;
    const next = scrollTopFor(selectedIndex, el.scrollTop, size.height, rowHeight);
    if (next !== el.scrollTop) el.scrollTop = next;
  }, [selectedIndex, selectedKey, sort, rowHeight, size.height, bodyRef]);

  const { onEndReached } = props;
  useEffect(() => {
    if (onEndReached && sorted.length > 0 && range.end >= sorted.length - 20) onEndReached();
  }, [onEndReached, range.end, sorted.length]);

  const move = useCallback(
    (delta: number) => {
      if (!onSelect || sorted.length === 0) return;
      const next = clampIndex(selectedIndex < 0 ? (delta > 0 ? 0 : sorted.length - 1) : selectedIndex + delta, sorted.length);
      const row = sorted[next];
      if (row !== undefined) onSelect(row);
    },
    [onSelect, sorted, selectedIndex],
  );

  const act = useCallback(
    (cmd: NavCommand) => {
      if (cmd.type === 'move') move(cmd.delta);
      const row = selectedIndex >= 0 ? sorted[selectedIndex] : undefined;
      if (!row) return;
      if (cmd.type === 'open') onOpen?.(row);
      if (cmd.type === 'copy' && props.copyText) {
        const text = props.copyText(row);
        navigator.clipboard.writeText(text).then(
          () => toast(`Copied ${text}`),
          () => toast('Copy failed: clipboard not available', 'error'),
        );
      }
    },
    [move, onOpen, props, selectedIndex, sorted, toast],
  );
  useNav(act, primary === true);

  const page = Math.max(1, Math.floor(size.height / rowHeight) - 1);
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.target !== e.currentTarget || e.ctrlKey || e.metaKey || e.altKey) return;
    let handled = true;
    if (e.key === 'ArrowDown') move(1);
    else if (e.key === 'ArrowUp') move(-1);
    else if (e.key === 'PageDown') move(page);
    else if (e.key === 'PageUp') move(-page);
    else if (e.key === 'Home') move(-sorted.length);
    else if (e.key === 'End') move(sorted.length);
    else if (e.key === 'Enter') act({ type: 'open' });
    else handled = false;
    if (handled) e.preventDefault();
  };

  const toggleSort = (c: Column<T>) => {
    setSort((s) => (s?.id !== c.id ? { id: c.id, dir: 'asc' } : s.dir === 'asc' ? { id: c.id, dir: 'desc' } : props.initialSort && props.initialSort.id !== c.id ? props.initialSort : null));
  };

  const showSkeleton = loading && rows.length === 0;
  const skeletonCount = Math.max(6, Math.min(40, Math.floor(size.height / rowHeight)));
  const activeId = selectedIndex >= range.start && selectedIndex < range.end ? `${gridId}-r${selectedIndex}` : undefined;

  return (
    <div
      ref={wrapRef}
      className="dt"
      style={style}
      role="grid"
      aria-label={props.label}
      aria-rowcount={sorted.length + 1}
      aria-colcount={columns.length}
      aria-busy={loading || undefined}
      aria-activedescendant={activeId}
      tabIndex={0}
      onKeyDown={onKeyDown}
    >
      <div className="dt-head" role="row" aria-rowindex={1}>
        {columns.map((c) => {
          const active = sort?.id === c.id;
          return (
            <div
              key={c.id}
              role="columnheader"
              className={c.align === 'right' ? 'right' : undefined}
              aria-sort={c.sortKey ? (active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none') : undefined}
            >
              {c.sortKey ? (
                <button type="button" className="dt-sort" data-active={active} onClick={() => toggleSort(c)} title={`Sort by ${c.header}`}>
                  {c.header}
                  {active && <Icon name={sort.dir === 'asc' ? 'sortAsc' : 'sortDesc'} />}
                </button>
              ) : (
                c.header
              )}
            </div>
          );
        })}
      </div>

      <div ref={bodyRef} className="dt-body" role="presentation" tabIndex={-1} onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}>
        {showSkeleton ? (
          <div role="presentation">
            {Array.from({ length: skeletonCount }, (_, i) => (
              <div key={i} className="dt-row skeleton" role="presentation">
                {columns.map((c) => (
                  <div key={c.id} role="presentation">
                    <div className="skeleton-bar" />
                  </div>
                ))}
              </div>
            ))}
          </div>
        ) : sorted.length === 0 ? (
          props.empty
        ) : (
          <div role="presentation" style={{ height: range.total }}>
            <div className="dt-rows" role="presentation" style={{ transform: `translateY(${range.offset}px)` }}>
              {sorted.slice(range.start, range.end).map((row, i) => {
                const index = range.start + i;
                const key = rowKey(row);
                return (
                  <div
                    key={key}
                    id={`${gridId}-r${index}`}
                    className="dt-row"
                    role="row"
                    aria-rowindex={index + 2}
                    aria-selected={key === selectedKey}
                    onClick={() => {
                      onSelect?.(row);
                      wrapRef.current?.focus({ preventScroll: true });
                    }}
                    onDoubleClick={() => onOpen?.(row)}
                  >
                    {columns.map((c) => (
                      <div key={c.id} role="gridcell" className={c.align === 'right' ? 'right num' : undefined} title={c.title?.(row)}>
                        {c.render(row)}
                      </div>
                    ))}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      <div className="dt-foot">
        <span className="num">
          {showSkeleton ? 'Loading' : `${fmtInt(sorted.length)} ${unitText(props.unit ?? 'rows', sorted.length)}`}
        </span>
        {props.footer}
        {selectedIndex >= 0 && <span className="num">row {fmtInt(selectedIndex + 1)} selected</span>}
      </div>
    </div>
  );
}
