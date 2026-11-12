// Text of the About page, the guided tour and the help chat's suggested questions (2026-11-13).
// Plain words; component names are the real module names in backend/app. The only numbers here are
// documented facts of the dev scenarios (docs/session-notes.md), never results.

export interface Stage {
  n: number;
  name: string;
  plain: string;
  components: string[];
}

export const PIPELINE: readonly Stage[] = [
  {
    n: 1,
    name: 'Ingest',
    plain: 'Read the recorded alerts as if they were arriving now, check every record and store it.',
    components: ['replay collector', 'stream (in-memory / Kafka)', 'alert normalizer', 'enrichment', 'SQLite / PostgreSQL stores'],
  },
  {
    n: 2,
    name: 'Detect and triage',
    plain: 'Tag alerts with ATT&CK techniques, re-check log lines with Sigma rules, and group related alerts into ranked incidents.',
    components: ['Wazuh, Suricata, AMiner alerts', 'Sigma engine', 'ATT&CK mapping', 'triage (gap 300 s, severity table)'],
  },
  {
    n: 3,
    name: 'Investigate',
    plain: 'A local language model reads one case through tools and answers attack or benign, citing alert ids.',
    components: ['single agent', 'LangGraph multi-agent graph', 'ATT&CK search (RAG)', 'matched budgets'],
  },
  {
    n: 4,
    name: 'Verify',
    plain: 'Check every citation and claim against the alerts; drop what the evidence does not support.',
    components: ['evidence verifier', 'case scoring (no AI judge)', 'baselines'],
  },
  {
    n: 5,
    name: 'Report and review',
    plain: 'Write reports, recommend playbook actions, and let a second person approve any action before it is (simulated) executed.',
    components: ['reports JSON / CSV / PDF', 'playbooks', 'four-eyes approvals', 'audit log', 'this console'],
  },
];

export const STUDY_QUESTION =
  'Detector-conditioned investigation: with the AI investigator held fixed, how much does the alert source it is given (Wazuh, Suricata, AMiner, all of them fused, or controls) change how many attack steps it finds and how often it claims things the evidence does not support?';

export const PROBLEM =
  'A security operations centre receives far more alerts than people can read. Most are harmless, and the ones that matter are spread across several tools. SentinelAI groups and ranks those alerts, lets an AI investigator explain them with citations, checks every citation, and keeps a person in charge of any response.';

export interface ScreenGuide {
  path: string;
  name: string;
  what: string;
  why: string;
}

export const SCREEN_GUIDE: readonly ScreenGuide[] = [
  { path: '/overview', name: 'Overview', what: 'Four headline numbers, alerts over time and the incidents to look at first.', why: 'The first question of a shift: is anything serious waiting?' },
  { path: '/incidents', name: 'Incidents', what: 'The ranked queue; each incident has a plain "What happened" line, a timeline, the entity graph and the evidence.', why: 'This is where an analyst works: one incident at a time, evidence first.' },
  { path: '/alerts', name: 'Alerts', what: 'Every stored alert, filterable by detector, rule, technique and host; repeats are folded into one row.', why: 'To check what an incident is made of, or search the raw log text.' },
  { path: '/approvals', name: 'Approvals', what: 'Requested response actions and who decided them, with the reason.', why: 'Shows the human-in-the-loop rule: nobody approves their own request.' },
  { path: '/reports', name: 'Reports', what: 'Incident reports with timeline, entity graph, techniques and recommended actions; JSON, CSV, PDF.', why: 'The written output a team hands on.' },
  { path: '/executive', name: 'Executive', what: 'One printable page for a manager: trend, top risks, review times.', why: 'The same data, summarised without raw records.' },
  { path: '/study', name: 'Study', what: 'Pilot results from the result files: coverage, citation precision and unsupported claims per arm and alert source.', why: 'This is the research measurement; it stays empty until a real run finishes.' },
  { path: '/ask', name: 'Ask', what: 'Questions to the local model about one incident, with verified citations.', why: 'Shows the investigator working on a real incident.' },
];

export const LIMITS: readonly string[] = [
  'All data is a replay of the published AIT-ADS dataset (recorded in 2022), not live traffic.',
  'Response actions are simulated: approving and executing records the decision, nothing is sent to any system.',
  'In each dev scenario 3 of the 10 attack phases left no linked alert in any detector, so no investigator can find them from alerts; coverage is reported over the 7 reachable phases.',
  'Suricata alerts almost never carry the dataset\'s event link (the authors matched them from network flows), so Suricata results carry a caveat.',
  'No threat-intelligence list is loaded: indicator (IOC) matches are "not measured", not zero.',
  'The console shows platform outputs only and never the dataset\'s labels; the Study page shows run-level rates from result files, labelled pilot or final.',
  'Held-out scenarios are not opened until the protocol is frozen.',
];

export interface TourStop {
  path: string;
  title: string;
  text: string;
}

export const TOUR: readonly TourStop[] = [
  { path: '/about', title: '1 of 6 · How SentinelAI works', text: 'The problem, the five pipeline stages and the one research question. Every "?" on any screen opens the same glossary.' },
  { path: '/overview', title: '2 of 6 · Overview', text: 'Four headline numbers, alerts over time, and the incidents to look at first, each named by its main host and time. More charts are under "More detail".' },
  { path: '/incidents', title: '3 of 6 · Incidents', text: 'The ranked queue. The detail starts with a plain "What happened" sentence built from the incident\'s own data, then the timeline, graph and evidence.' },
  { path: '/alerts', title: '4 of 6 · Alerts', text: 'The raw alerts behind every incident. Thousands of identical repeats are folded into one row; open a row to see its log lines.' },
  { path: '/approvals', title: '5 of 6 · Approvals', text: 'A response action needs a second person: the requester cannot approve it, a reason is required, and execution is simulated.' },
  { path: '/study', title: '6 of 6 · Study', text: 'The research results: the same investigator on different alert sources, before and after the evidence verifier. Pilot numbers are labelled as pilot.' },
];

export const SUGGESTED: Record<string, string[]> = {
  '/about': ['What is a detector?', 'What does the verifier do?', 'What is a held-out scenario?'],
  '/overview': ['What is an incident?', 'Why is IOC not measured?', 'What does the triage gap mean?'],
  '/incidents': ['What happened in this incident?', 'What does triage rule H2 mean?', 'What is the entity graph?'],
  '/alerts': ["What is the detector's own severity?", 'What is an ATT&CK technique?', 'Why are rows folded together?'],
  '/approvals': ['What is four-eyes approval?', 'What does simulated execution mean?', 'What is a playbook?'],
  '/reports': ['What is a citation?', 'What is a playbook?', 'What is the entity graph?'],
  '/executive': ['What is incident severity?', 'What is the attack chain?', 'What is a dataset replay?'],
  '/study': ['What is coverage?', 'What is the noise control?', 'What is an unsupported claim?'],
  '/ask': ['What is the copilot?', 'What is an unsupported claim?', 'What is a citation?'],
};
