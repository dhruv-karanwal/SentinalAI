import '@fontsource-variable/geist/wght.css';
import '@fontsource-variable/geist-mono/wght.css';
import './tokens.css';
import './base.css';
import './system.css';
import './shell.css';
import './dash.css';
import './work.css';
import './about.css';

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { App } from './App.tsx';

const root = document.getElementById('root');
if (!root) throw new Error('#root is missing');
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
