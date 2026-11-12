// The one glossary of the console (2026-11-13). Every <Term> tooltip, the About page's glossary
// section and the help chat's offline answers read from here, so a term is explained the same way
// everywhere. Rules: plain words, a definition of at most two sentences, and "why it matters here"
// says what the term changes in this project. Facts only from the code and docs (no numbers that
// the API does not serve, except the documented ones in `about.ts`).

export interface GlossaryTerm {
  id: string;
  term: string;
  /** other words a reader may type (the chat's offline search matches these too) */
  aliases: string[];
  definition: string;
  why: string;
  /** the screen where the term is best seen */
  see?: string;
}

export const GLOSSARY: readonly GlossaryTerm[] = [
  {
    id: 'alert',
    term: 'Alert',
    aliases: ['alerts', 'detection'],
    definition: 'A message a security tool raises when something in a log or network flow matches one of its rules or looks unusual. One alert points at one moment and usually one host.',
    why: 'Alerts are the raw input of everything here: incidents, charts, reports and the AI investigation are all built from stored alerts.',
    see: '/alerts',
  },
  {
    id: 'incident',
    term: 'Incident',
    aliases: ['incidents', 'case'],
    definition: 'A group of related alerts that an analyst reviews as one piece of work. SentinelAI groups alerts that share a host or source IP and follow each other within the triage gap.',
    why: 'Analysts work incident by incident, not alert by alert: 11,000 alerts can become one incident to review.',
    see: '/incidents',
  },
  {
    id: 'detector',
    term: 'Detector',
    aliases: ['detectors', 'alert source', 'sensor'],
    definition: 'A security tool that produces alerts. This dataset has three: Wazuh (rule-based host monitoring), Suricata (network signatures) and AMiner (log anomaly detection).',
    why: 'The research question is how much the choice of detector changes what an AI investigator can find.',
  },
  {
    id: 'wazuh',
    term: 'Wazuh',
    aliases: ['ossec'],
    definition: 'An open-source host monitoring tool that reads system and application logs and raises an alert when a log line matches one of its rules. Each rule has a level from 0 to 15.',
    why: 'Most alerts in the dev scenarios come from Wazuh, and it is the only detector that ships ATT&CK technique ids with its rules.',
  },
  {
    id: 'suricata',
    term: 'Suricata',
    aliases: ['ids', 'network ids'],
    definition: 'An open-source network intrusion detection system that inspects traffic and raises an alert when a packet stream matches a signature. Priority 1 is its most serious.',
    why: 'It sees the network side of an attack; Wazuh also copies some Suricata alerts, and those copies are marked as duplicates.',
  },
  {
    id: 'aminer',
    term: 'AMiner',
    aliases: ['logdata anomaly miner', 'anomaly detector'],
    definition: 'An anomaly detector from the dataset authors (AIT) that learns what normal log lines look like and alerts on lines or value patterns it has not seen before.',
    why: 'It can catch behaviour no rule describes, but its alerts carry no severity and no ATT&CK mapping.',
  },
  {
    id: 'sigma',
    term: 'Sigma',
    aliases: ['sigma rule', 'sigma rules'],
    definition: 'A shared, vendor-neutral format for detection rules. SentinelAI runs 90 of the 256 approved SigmaHQ Linux and web rules over the log lines that other detectors already alerted on.',
    why: 'It adds ATT&CK tags to existing evidence; it is a platform extra, not one of the detectors the study compares.',
  },
  {
    id: 'attack-tactic',
    term: 'ATT&CK tactic',
    aliases: ['tactic', 'tactics', 'mitre tactic'],
    definition: 'One of the attacker goals in the MITRE ATT&CK framework, such as Initial Access, Credential Access or Exfiltration. Tactics answer "what was the attacker trying to achieve?".',
    why: 'Tactics give the columns of the ATT&CK charts and the stages of the attack chain strip.',
  },
  {
    id: 'attack-technique',
    term: 'ATT&CK technique',
    aliases: ['technique', 'techniques', 'mitre', 'ttp', 'T1078'],
    definition: 'A specific way to reach a tactic, with an id such as T1078 (Valid Accounts). MITRE ATT&CK is a public catalogue of observed attacker behaviour.',
    why: 'An alert is mapped to a technique only from the detector\'s own id or a fixed, documented rule table; nothing is guessed.',
  },
  {
    id: 'kill-chain',
    term: 'Attack chain',
    aliases: ['kill chain', 'stages'],
    definition: 'The tactics of an attack laid out in their usual order, from reconnaissance to impact. Each cell shows how many mapped alerts point to that stage.',
    why: 'Gaps show stages with no mapped alert; a gap means "no evidence here", not "nothing happened".',
  },
  {
    id: 'severity',
    term: 'Detector\'s own severity',
    aliases: ['level', 'detector-native level', 'rule level', 'priority'],
    definition: 'The importance number the detector itself gives an alert: Wazuh rule level 0-15 (higher is worse), Suricata priority 1-3 (1 is worst), none for AMiner.',
    why: 'The console shows these numbers as the detector reported them and never rescales them; only triage turns them into High / Medium / Low.',
  },
  {
    id: 'incident-severity',
    term: 'Incident severity',
    aliases: ['high', 'medium', 'low', 'severity class'],
    definition: 'High, Medium or Low for a whole incident, set by the first matching row of the triage severity table. It ranks the queue; it is not a verdict that an attack happened.',
    why: 'It decides which incident the queue shows first.',
  },
  {
    id: 'triage-rule',
    term: 'Triage rule',
    aliases: ['severity rule', 'H1', 'H2', 'H3', 'M1', 'M2', 'M3', 'L1', 'severity table'],
    definition: 'A row of the fixed severity table: H1 an indicator matched, H2 three or more detectors agree, H3 a high-level alert that is ATT&CK-mapped or seen by two detectors, M1-M3 weaker signals, L1 anything else.',
    why: 'Every incident says which row made it severe, so the ranking can be checked by hand.',
  },
  {
    id: 'triage-gap',
    term: 'Triage gap',
    aliases: ['gap', 'gap seconds', '300 s'],
    definition: 'The longest pause, in seconds, allowed between two alerts of the same host or source IP for them to stay in one incident. The default is 300 s (5 minutes).',
    why: 'A larger gap makes fewer, bigger incidents; the gap is printed with every incident number.',
  },
  {
    id: 'entity',
    term: 'Entity',
    aliases: ['host', 'source ip', 'ip address', 'entities'],
    definition: 'A host (the machine an alert is about) or a source IP address (where traffic came from). Entities connect alerts into incidents and draw the entity graph.',
    why: 'Naming an incident by its main host or IP is what makes two incidents with the same rule tell apart.',
  },
  {
    id: 'entity-graph',
    term: 'Entity graph',
    aliases: ['graph', 'network graph'],
    definition: 'A drawing of which source IPs talked to which hosts in an incident: squares are source IPs, circles are hosts, and a thicker line means more alerts.',
    why: 'It shows at a glance whether one attacker hit one machine or many; the table under it lists every edge.',
  },
  {
    id: 'ioc',
    term: 'IOC',
    aliases: ['indicator of compromise', 'indicator', 'threat intel', 'not measured'],
    definition: 'An indicator of compromise: a known-bad value such as an IP address, domain or file hash from a threat-intelligence list.',
    why: 'No indicator list is loaded (the online feeds need keys and are disabled), so IOC matches are shown as "not measured", never as 0 %.',
  },
  {
    id: 'duplicate',
    term: 'Duplicate alert',
    aliases: ['duplicates', 'fast.log', 'twin'],
    definition: 'A Wazuh alert that only repeats a Suricata alert (Wazuh reads Suricata\'s fast.log file). The pair is matched and the copy is flagged.',
    why: 'Copies are excluded from evaluation by default so one network event is not counted twice.',
  },
  {
    id: 'evidence',
    term: 'Evidence',
    aliases: ['log line', 'raw log', 'raw record'],
    definition: 'What an alert carries: the raw log lines that triggered it, its fields and the original record. SentinelAI never adds evidence the alert did not have.',
    why: 'Every claim the AI makes must be checkable against this evidence.',
  },
  {
    id: 'citation',
    term: 'Citation',
    aliases: ['cited alert', 'cites', 'citations'],
    definition: 'An alert id that an AI answer points to as support for a finding. A citation is a link into that alert\'s evidence.',
    why: 'Citations are scored: citing an attack alert is good, citing an unrelated or invented id counts as wrong.',
  },
  {
    id: 'verifier',
    term: 'Evidence verifier',
    aliases: ['verifier', 'verification', 'verified', 'dropped'],
    definition: 'A deterministic checker (no AI) that removes citations to alerts outside the case and claims that do not match the cited alert\'s fields or log text exactly.',
    why: 'Results are reported before and after the verifier; what it drops is shown, never hidden.',
  },
  {
    id: 'unsupported-claim',
    term: 'Unsupported claim',
    aliases: ['hallucination', 'unsupported', 'claim'],
    definition: 'A statement in an AI answer about an alert (a field value or a quoted log text) that the alert does not actually contain.',
    why: 'The rate of unsupported claims before the verifier is the study\'s measure of hallucination.',
  },
  {
    id: 'coverage',
    term: 'Coverage',
    aliases: ['attack-step coverage', 'phase coverage', 'recall'],
    definition: 'The share of attack phases for which an investigation cited at least one alert that belongs to that phase.',
    why: 'It is the study\'s headline number: does the investigator find each step of the attack?',
    see: '/study',
  },
  {
    id: 'reachable-phase',
    term: 'Alert-reachable phase',
    aliases: ['reachable', 'unreachable', 'phase', 'attack phase'],
    definition: 'An attack phase in which at least one detector raised an alert that the dataset authors linked to the attack. In each dev scenario 7 of the 10 phases are reachable.',
    why: 'No investigator can cite an alert that does not exist, so the headline coverage counts reachable phases only.',
  },
  {
    id: 'agent',
    term: 'Investigation agent',
    aliases: ['single agent', 'llm agent', 'ai agent', 'model'],
    definition: 'A local language model that reads a case through a small set of tools (list, get, search alerts, read raw logs) and answers attack or benign with cited findings.',
    why: 'The agent stays fixed while the alert source changes; that is what makes the comparison fair.',
  },
  {
    id: 'multi-agent',
    term: 'Multi-agent graph',
    aliases: ['langgraph', 'graph arm', 'supervisor'],
    definition: 'Six model roles (log analysis, correlation, knowledge retrieval, anomaly analysis, investigation, report writing) coordinated by a supervisor. They share notes and work the same case under the same budget as the single agent.',
    why: 'The pilot compares single agent against graph on the same cases, budgets and verifier.',
  },
  {
    id: 'matched-budget',
    term: 'Matched budget',
    aliases: ['budget', 'token budget', 'tool budget'],
    definition: 'Both arms get the same limit of tool calls and tokens per case, with a hard stop.',
    why: 'Without it the bigger system could win only because it spent more.',
  },
  {
    id: 'baseline',
    term: 'Baseline',
    aliases: ['baselines', 'cite-all', 'top-k', 'reference line'],
    definition: 'A simple non-AI rule for choosing alerts to cite, for example "cite every alert" (the ceiling) or "cite the top k by detector order".',
    why: 'An AI result means something only next to what a trivial rule gets on the same cases.',
  },
  {
    id: 'oracle',
    term: 'Oracle control',
    aliases: ['oracle'],
    definition: 'An alert source that keeps only the alerts the dataset authors linked to the attack. No real detector can produce it.',
    why: 'It shows the best case: how well the agent does when every alert it sees is relevant.',
  },
  {
    id: 'noise',
    term: 'Noise control',
    aliases: ['noise', 'noise-wazuh', 'random control'],
    definition: 'An alert source made of benign alerts only, as many as the detector it imitates would show in the same window.',
    why: 'If the agent still "covers" the attack on noise, the measure is broken; event-label coverage on noise must stay at zero.',
  },
  {
    id: 'shuffled',
    term: 'Shuffled control',
    aliases: ['shuffled', 'shuffled pool'],
    definition: 'A random draw of alerts from the whole pool with the same count as a detector, kept from an earlier design for comparison.',
    why: 'It separates "more alerts" from "the right alerts"; it is never a headline variant.',
  },
  {
    id: 'dataset-replay',
    term: 'Dataset replay',
    aliases: ['replay', 'demo data', 'replayed'],
    definition: 'The alerts shown are not live traffic: they are read from the published AIT-ADS files and fed through the platform as if they had just arrived.',
    why: 'Dates in the data are from 2022 (when the dataset was recorded); dates of incidents, reports and approvals are when this console created them.',
  },
  {
    id: 'ait-ads',
    term: 'AIT-ADS',
    aliases: ['dataset', 'ait alert data set', 'russellmitchell', 'shaw', 'scenario'],
    definition: 'The AIT Alert Data Set: alerts from Wazuh, Suricata and AMiner recorded during simulated multi-step attacks on eight small company networks, with the authors\' labels.',
    why: 'Each network is a scenario; russellmitchell and shaw are the dev scenarios used for building and the pilot.',
  },
  {
    id: 'dev-scenario',
    term: 'Dev scenario',
    aliases: ['dev', 'development scenario', 'pilot data'],
    definition: 'A scenario used while building and tuning: russellmitchell and shaw. Everything this console shows comes from them.',
    why: 'Numbers on dev scenarios are pilot material, never paper results.',
  },
  {
    id: 'held-out',
    term: 'Held-out scenario',
    aliases: ['held out', 'test scenario', 'heldout'],
    definition: 'A scenario kept untouched until the protocol is frozen: fox, harrison, santos, wardbeck, wheeler and wilson. Code refuses to open them without a matching freeze.',
    why: 'Final results come only from these, so tuning on dev cannot leak into the reported numbers.',
  },
  {
    id: 'pilot',
    term: 'Pilot',
    aliases: ['pilot run', 'matched run'],
    definition: 'The first real run of both arms on the dev scenarios, with the local model, to check the method and estimate cost before the final runs.',
    why: 'Its numbers decide whether the method is ready; they are labelled pilot and never presented as final.',
    see: '/study',
  },
  {
    id: 'four-eyes',
    term: 'Four-eyes approval',
    aliases: ['approval', 'approvals', 'four eyes', 'two-person rule'],
    definition: 'A response action (for example blocking an IP) needs a second person to approve it: the requester cannot decide their own request, and a decision needs a written reason.',
    why: 'Nothing runs without an approved request, and each approval can be executed once.',
    see: '/approvals',
  },
  {
    id: 'simulated',
    term: 'Simulated execution',
    aliases: ['simulated', 'executor', 'execute'],
    definition: 'Executing an approved action only records that it would have run; no firewall or other system is contacted.',
    why: 'The workflow can be shown end to end without any risk to real systems.',
  },
  {
    id: 'playbook',
    term: 'Playbook',
    aliases: ['playbooks', 'recommendation', 'response action'],
    definition: 'A fixed list of recommended response steps for an ATT&CK technique, such as "reset the credentials" for Valid Accounts (T1078).',
    why: 'Recommendations come from this table, not from the AI.',
  },
  {
    id: 'copilot',
    term: 'Copilot',
    aliases: ['ask', 'assistant', 'chat'],
    definition: 'Questions to the local model about one incident; the answer goes through the evidence verifier before it is shown.',
    why: 'It is a demo feature, never a study result, and it needs the local model to be running.',
  },
  {
    id: 'data-date',
    term: 'Data date vs created date',
    aliases: ['dates', '2022', 'created', 'data time'],
    definition: 'A data date is when an alert happened in the 2022 dataset. A created date is when this console stored an incident, report or approval.',
    why: 'Both appear side by side, so each is labelled; "age in queue" counts from the created date.',
  },
];

const byId = new Map(GLOSSARY.map((t) => [t.id, t]));

export function glossaryTerm(id: string): GlossaryTerm | undefined {
  return byId.get(id);
}
