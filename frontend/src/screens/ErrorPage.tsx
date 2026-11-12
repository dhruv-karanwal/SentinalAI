// One error page for unknown routes, missing data sources and API outages: what happened, what
// still works, and a way back.

import { Button } from '../components/ui.tsx';
import { Icon } from '../icons.tsx';

export function ErrorPage({ title, detail, home, onRetry }: { title: string; detail: string; home: string; onRetry?: () => void }) {
  return (
    <div className="page">
      <div className="state" data-kind="error" role="alert" style={{ maxWidth: 640, margin: '48px auto' }}>
        <div className="state-title">
          <Icon name="warning" />
          {title}
        </div>
        <p>{detail}</p>
        <p className="muted">The rest of the console still works: use the rail on the left, or go to the start page.</p>
        <p style={{ display: 'flex', gap: 'var(--sp-8)' }}>
          <a className="btn" href={`#${home}`}>
            Go to the start page
          </a>
          {onRetry && (
            <Button icon="refresh" onClick={onRetry}>
              Retry
            </Button>
          )}
        </p>
      </div>
    </div>
  );
}
