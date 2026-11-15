// One error page for unknown routes, missing data sources and API outages: what happened, what
// still works, and a way back.

import { Button } from '../components/ui.tsx';
import { Icon } from '../icons.tsx';

export function ErrorPage({ title, detail, home, onRetry }: { title: string; detail: string; home: string; onRetry?: () => void }) {
  return (
    <div className="page">
      <div className="err-page" role="alert">
        <span className="err-icon" aria-hidden="true">
          <Icon name="warning" />
        </span>
        <h1>{title}</h1>
        <p>{detail}</p>
        <p className="err-note">The rest of the console still works: use the navigation, the command palette (Ctrl+K), or go to the start page.</p>
        <div className="err-actions">
          <a className="btn" href={`#${home}`}>
            Go to the start page
          </a>
          {onRetry && (
            <Button icon="refresh" onClick={onRetry}>
              Retry
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
