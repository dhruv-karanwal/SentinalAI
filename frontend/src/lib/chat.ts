// Floating help chat state (DESIGN.md 13.4): pure reducer, focus-trap arithmetic, error notes,
// suggested questions and session storage. The component (components/HelpChat.tsx) only wires these.

import { SUGGESTED } from '../content/about.ts';

export interface ChatMsg {
  id: number;
  who: 'you' | 'help';
  text: string;
  /** who answered: the model id, or 'glossary' */
  by?: string;
  terms?: string[];
  note?: string;
}

export interface ChatState {
  open: boolean;
  minimised: boolean;
  wide: boolean;
  msgs: ChatMsg[];
  /** set by close: the component moves focus back to the button, then clears it */
  returnFocus: boolean;
}

export type ChatAction =
  | { type: 'open' }
  | { type: 'close' }
  | { type: 'minimise' }
  | { type: 'wide' }
  | { type: 'clear' }
  | { type: 'focused' }
  | { type: 'push'; msg: ChatMsg };

/** history kept per browser session; older messages fall off */
export const CHAT_LIMIT = 40;
const KEY = 'sentinel.chat';

export const initialChat = (): ChatState => ({ open: false, minimised: false, wide: false, msgs: [], returnFocus: false });

export function chatReducer(s: ChatState, a: ChatAction): ChatState {
  switch (a.type) {
    case 'open':
      return { ...s, open: true, minimised: false };
    case 'close':
      return { ...s, open: false, returnFocus: true };
    case 'minimise':
      return { ...s, minimised: !s.minimised };
    case 'wide':
      return { ...s, wide: !s.wide };
    case 'clear':
      return { ...s, msgs: [] };
    case 'focused':
      return { ...s, returnFocus: false };
    case 'push':
      return { ...s, msgs: [...s.msgs, a.msg].slice(-CHAT_LIMIT) };
  }
}

/** Tab inside a dialog: the index to focus instead, or null to let the browser move on. */
export function nextFocus(count: number, current: number, shift: boolean): number | null {
  if (count === 0) return null;
  if (current < 0) return shift ? count - 1 : 0;
  if (!shift && current === count - 1) return 0;
  if (shift && current === 0) return count - 1;
  return null;
}

/** What the chat says when the explain request fails, and whether the model counts as offline. */
export function errorNote(status: number, message: string): { note: string; offline: boolean } {
  if (status === 429) return { note: 'The local model is busy with another request; showing the glossary answer instead.', offline: false };
  if (status === 0 || status === 502 || status === 503 || status === 504) return { note: 'Local model offline: showing glossary answers only.', offline: true };
  return { note: `The help request failed (${status || 'no answer'}${message ? `: ${message}` : ''}); showing the glossary answer.`, offline: false };
}

export const suggestionsFor = (path: string): string[] => SUGGESTED[path] ?? SUGGESTED['/about'] ?? [];

interface Store {
  getItem(k: string): string | null;
  setItem(k: string, v: string): void;
}

const isMsg = (m: unknown): m is ChatMsg => {
  if (typeof m !== 'object' || m === null) return false;
  const r = m as Record<string, unknown>;
  return typeof r.id === 'number' && (r.who === 'you' || r.who === 'help') && typeof r.text === 'string';
};

export function loadChat(store: Store | null): ChatState {
  try {
    const raw = store?.getItem(KEY);
    if (!raw) return initialChat();
    const d = JSON.parse(raw) as Record<string, unknown>;
    const msgs = Array.isArray(d.msgs) ? d.msgs.filter(isMsg).slice(-CHAT_LIMIT) : [];
    return { ...initialChat(), open: d.open === true, wide: d.wide === true, msgs };
  } catch {
    return initialChat();
  }
}

export function saveChat(store: Store | null, s: ChatState): void {
  try {
    store?.setItem(KEY, JSON.stringify({ open: s.open, wide: s.wide, msgs: s.msgs }));
  } catch {
    // storage blocked (private window, quota): the chat still works, it just forgets on reload
  }
}

export function sessionStore(): Store | null {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}
