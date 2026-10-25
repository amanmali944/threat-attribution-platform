import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Crosshair,
  Terminal,
  Activity,
  Layers,
  ShieldAlert,
  Server,
  Clock,
  ExternalLink,
  Copy,
  Check,
  Trash2,
  RefreshCw,
  Zap,
} from 'lucide-react';
import { api, type SimulationResult } from './services/api';

interface Scenario {
  id: string;
  code: string;
  name: string;
  vector: string;
  difficulty: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  techniques: string[];
  description: string;
  expectedTelemetry: string;
}

interface TerminalLog {
  id: string;
  timestamp: string;
  level: 'PAYLOAD' | 'SCAN' | 'EXPLOIT' | 'CRITICAL' | 'EXFIL' | 'SYS' | 'SUCCESS' | 'ERROR' | 'WARN';
  target: string;
  message: string;
  isError?: boolean;
  isSuccess?: boolean;
}

const ATTACK_SCENARIOS: Scenario[] = [
  {
    id: 'apt29_intrusion',
    code: 'APT29-INTRUSION',
    name: 'APT29 / Cozy Bear Multi-Stage Intrusion',
    vector: 'Identity VPN Gateway -> Intranet Web -> Host Privilege Escalation -> DNS Exfiltration',
    difficulty: 'CRITICAL',
    techniques: ['T1078 (Valid Accounts)', 'T1595 (Active Scan)', 'T1548 (Privilege Escalation)', 'T1003.008 (/etc/shadow)', 'T1071.004 (DNS Tunneling)'],
    description: 'Executes full multi-layer kill chain: stolen VPN credential access, internal endpoint fuzzing, web shell execution, root password file harvesting, and DNS tunneling exfiltration.',
    expectedTelemetry: '6 Fused Alerts across 4 Layers -> 1 Critical Incident -> Attribution Root Node',
  },
  {
    id: 'ssh_bruteforce',
    code: 'SSH-BRUTEFORCE',
    name: 'SSH Brute-Force & Private Key Extraction',
    vector: 'Identity SSH (Port 22) -> Perimeter Bastion -> Lateral Host Access',
    difficulty: 'HIGH',
    techniques: ['T1110.001 (Password Guessing)', 'T1110 (Brute Force Burst)', 'T1003.008 (Private Keys)'],
    description: 'High-frequency dictionary attack against SSH bastion gateway. 12 failed attempts followed by account compromise and root SSH private key theft.',
    expectedTelemetry: '3 Fused Alerts -> 1 Correlated Incident -> Credential Access TTPs',
  },
  {
    id: 'dns_tunneling',
    code: 'DNS-TUNNELING',
    name: 'High-Entropy DNS Protocol C2 Tunnel',
    vector: 'Network UDP/53 -> External C2 Nameserver (Covert Channel)',
    difficulty: 'HIGH',
    techniques: ['T1071.004 (DNS Protocol C2)', 'T1048 (Covert Channel Exfiltration)'],
    description: 'Bypasses perimeter firewall via covert Iodine/DNSCat channel. Streams encrypted payloads inside 16 long-name subdomains exceeding 110 characters.',
    expectedTelemetry: '1-2 Exfiltration Fused Alerts -> 1 Network Incident',
  },
  {
    id: 'privilege_escalation',
    code: 'PRIVILEGE-ESCALATION',
    name: 'Service Account Sudo & Shadow Exploitation',
    vector: 'Endpoint Host -> Local Service Account -> Root Shell Elevation',
    difficulty: 'CRITICAL',
    techniques: ['T1548.003 (Sudoers Abuse)', 'T1003.008 (/etc/shadow)', 'T1098 (Role Change)'],
    description: 'Web service account www-data leverages privilege escalation flaw to spawn interactive root bash shell, dump shadow hashes, and alter system roles.',
    expectedTelemetry: '2-3 Privilege Escalation Fused Alerts -> 1 Critical Incident',
  },
  {
    id: 'web_recon',
    code: 'WEB-RECON',
    name: 'Web Application Directory Traversal & Fuzzing',
    vector: 'Application HTTP/HTTPS -> Public Web Portal -> Sensitive Discovery',
    difficulty: 'MEDIUM',
    techniques: ['T1595.002 (Vulnerability Scan)', 'T1083 (File Discovery)', 'T1548 (Privilege Op)'],
    description: 'Automated Nikto/ffuf directory scanner executing 35 rapid 404 probes against sensitive paths (.git, .env, admin.php) followed by an exposed RCE hook invocation.',
    expectedTelemetry: '3 Reconnaissance Fused Alerts -> 1 Application Incident',
  },
];

export default function App() {
  const [activeScenarioId, setActiveScenarioId] = useState<string | null>(null);
  const [isLaunching, setIsLaunching] = useState(false);
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const [missionSeconds, setMissionSeconds] = useState(0);
  const [filterMode, setFilterMode] = useState<'ALL' | 'SUCCESS' | 'ERRORS'>('ALL');
  const [copied, setCopied] = useState(false);

  // Dynamic Telemetry State Counters
  const [injectedEventsCount, setInjectedEventsCount] = useState(0);
  const [fusedAlertsCount, setFusedAlertsCount] = useState(0);
  const [correlatedIncidentsCount, setCorrelatedIncidentsCount] = useState(0);
  const [activeExecutionsCount, setActiveExecutionsCount] = useState(0);
  const [lastIncidentId, setLastIncidentId] = useState<string | null>(null);

  // Terminal Logs State
  const [logs, setLogs] = useState<TerminalLog[]>([
    {
      id: 'init-1',
      timestamp: new Date().toISOString().substring(11, 19),
      level: 'SYS',
      target: '127.0.0.1:8000',
      message: 'Red Team C2 simulator interface initialized. Monitoring backend health on Port 8000.',
    },
    {
      id: 'init-2',
      timestamp: new Date().toISOString().substring(11, 19),
      level: 'SYS',
      target: 'TENANT: tenant-default-001',
      message: 'Operator session armed. Select an attack scenario to inject real-time telemetry stream.',
    },
  ]);

  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll terminal
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  // Mission Elapsed Clock
  useEffect(() => {
    const timer = setInterval(() => {
      setMissionSeconds((prev) => prev + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const formatMissionTime = (secs: number) => {
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    return `T+${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  };

  // Live Backend Health Polling (Every 5 seconds)
  const pollHealth = useCallback(async () => {
    const online = await api.checkHealth();
    setBackendOnline(online);
  }, []);

  useEffect(() => {
    pollHealth();
    const interval = setInterval(pollHealth, 5000);
    return () => clearInterval(interval);
  }, [pollHealth]);

  // Launch Attack Scenario
  const handleLaunchScenario = async (scenario: Scenario) => {
    if (isLaunching) return;
    setIsLaunching(true);
    setActiveScenarioId(scenario.id);

    const now = new Date().toISOString().substring(11, 19);
    setLogs((prev) => [
      ...prev,
      {
        id: `dispatch-${Date.now()}`,
        timestamp: now,
        level: 'CRITICAL',
        target: scenario.code,
        message: `DISPATCHING SCENARIO [${scenario.name}] -> POST http://127.0.0.1:8000/api/v1/demo/simulate`,
      },
    ]);

    try {
      const result: SimulationResult = await api.simulateAttack({
        scenario_id: scenario.id,
        tenant_id: 'tenant-default-001',
      });

      // Stream returned payload logs
      if (result.execution_logs && result.execution_logs.length > 0) {
        result.execution_logs.forEach((logItem, idx) => {
          setTimeout(() => {
            setLogs((prev) => [
              ...prev,
              {
                id: `log-${Date.now()}-${idx}`,
                timestamp: logItem.timestamp || new Date().toISOString().substring(11, 19),
                level: (logItem.level as any) || 'PAYLOAD',
                target: logItem.target || 'TARGET',
                message: logItem.message,
                isSuccess: logItem.level === 'EXFIL' || logItem.level === 'BREACH',
              },
            ]);
          }, (idx + 1) * 160);
        });
      }

      // Final completion entry & Counter Updates
      const finishDelay = (result.execution_logs?.length || 1) * 160 + 200;
      setTimeout(() => {
        const incId = result.incident_id || (result.incident_ids && result.incident_ids[0]) || 'inc-created';
        setLastIncidentId(incId);

        setLogs((prev) => [
          ...prev,
          {
            id: `done-${Date.now()}`,
            timestamp: new Date().toISOString().substring(11, 19),
            level: 'SUCCESS',
            target: 'PLATFORM_DB',
            message: `SUCCESS: Injected ${result.injected_events} events -> Generated ${result.alerts_generated} alerts -> Correlated incident [${incId}] in SQLite.`,
            isSuccess: true,
          },
        ]);

        // Dynamically increment counters
        setInjectedEventsCount((prev) => prev + (result.injected_events || 0));
        setFusedAlertsCount((prev) => prev + (result.alerts_generated || 0));
        setCorrelatedIncidentsCount((prev) => prev + (result.incidents_generated || 1));
        setActiveExecutionsCount((prev) => prev + 1);

        setIsLaunching(false);
      }, finishDelay);
    } catch (err: any) {
      setLogs((prev) => [
        ...prev,
        {
          id: `err-${Date.now()}`,
          timestamp: new Date().toISOString().substring(11, 19),
          level: 'ERROR',
          target: 'API_ERROR',
          message: `FAILED: ${err.message || 'Connection refused on Port 8000'}`,
          isError: true,
        },
      ]);
      setIsLaunching(false);
    }
  };

  const handleClearLogs = () => {
    setLogs([
      {
        id: `clear-${Date.now()}`,
        timestamp: new Date().toISOString().substring(11, 19),
        level: 'SYS',
        target: 'CONSOLE',
        message: 'Terminal logs cleared by operator.',
      },
    ]);
  };

  const handleCopyLogs = () => {
    const text = logs.map((l) => `[${l.timestamp}] [${l.level}] [${l.target}] ${l.message}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const filteredLogs = logs.filter((log) => {
    if (filterMode === 'ALL') return true;
    if (filterMode === 'SUCCESS') return log.isSuccess || log.level === 'SUCCESS' || log.level === 'EXFIL';
    if (filterMode === 'ERRORS') return log.isError || log.level === 'ERROR' || log.level === 'WARN';
    return true;
  });

  return (
    <div className="app-container">
      {/* ====================================================================
          1. HEADER HUD: Platform Title, Status Pill, Mission Timer, Tenant
         ==================================================================== */}
      <header className="top-nav">
        <div className="brand-section">
          <div className="brand-icon-box">
            <Crosshair size={20} />
          </div>
          <div>
            <h1 className="brand-title">RED TEAM COMMAND CONSOLE</h1>
            <p className="brand-subtitle">ADVERSARY ATTACK SIMULATOR &amp; TELEMETRY INJECTOR</p>
          </div>
        </div>

        <div className="hud-stats-group">
          {/* Mission Elapsed Time */}
          <div className="hud-pill">
            <Clock size={13} color="#8892B0" />
            <span className="hud-label">MISSION TIME:</span>
            <span className="hud-value">{formatMissionTime(missionSeconds)}</span>
          </div>

          {/* Tenant Scoping */}
          <div className="hud-pill">
            <Server size={13} color="#8892B0" />
            <span className="hud-label">TARGET TENANT:</span>
            <span className="hud-value">tenant-default-001</span>
          </div>

          {/* C2 Connection Status Pill */}
          <div className="hud-pill">
            <div className={`status-indicator ${backendOnline ? 'online' : 'offline'}`} />
            <span className="hud-label">C2 API (8000):</span>
            <span className={`hud-value ${backendOnline ? 'highlight-green' : 'highlight-red'}`}>
              {backendOnline === true ? 'ONLINE' : backendOnline === false ? 'DISCONNECTED' : 'POLLING'}
            </span>
          </div>
        </div>
      </header>

      {/* ====================================================================
          2. REAL-TIME METRICS STRIP: Dynamic Counters
         ==================================================================== */}
      <section className="metrics-strip">
        <div className="metric-card active-stat">
          <div className="metric-card-title">TOTAL INJECTED EVENTS</div>
          <div className="metric-card-number">{injectedEventsCount}</div>
          <div className="metric-card-sub">Raw telemetry rows posted</div>
        </div>

        <div className="metric-card active-stat">
          <div className="metric-card-title">FUSED ALERTS GENERATED</div>
          <div className="metric-card-number" style={{ color: '#FF0033' }}>
            {fusedAlertsCount}
          </div>
          <div className="metric-card-sub">Rules + ML detections triggered</div>
        </div>

        <div className="metric-card success-stat">
          <div className="metric-card-title">CORRELATED INCIDENTS</div>
          <div className="metric-card-number" style={{ color: '#00FF66' }}>
            {correlatedIncidentsCount}
          </div>
          <div className="metric-card-sub">
            {lastIncidentId ? `Latest: ${lastIncidentId}` : 'Multi-layer cases formed'}
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-card-title">ACTIVE EXECUTIONS</div>
          <div className="metric-card-number">{activeExecutionsCount}</div>
          <div className="metric-card-sub">Simulations dispatched</div>
        </div>
      </section>

      {/* ====================================================================
          3. MAIN 2-COLUMN WORKSPACE: Scenarios (Left) & Terminal (Right)
         ==================================================================== */}
      <div className="main-workspace">
        {/* Left Column: Attack Vector Scenarios */}
        <section className="section-panel">
          <div className="section-panel-header">
            <div className="section-panel-title">
              <Zap size={14} color="#FF0033" />
              <span>ATTACK SCENARIOS</span>
            </div>
            <span className="section-panel-count">5 ARMED</span>
          </div>

          <div className="scenarios-list">
            {ATTACK_SCENARIOS.map((scenario) => {
              const isSelected = activeScenarioId === scenario.id;
              const isThisExecuting = isLaunching && isSelected;

              return (
                <div
                  key={scenario.id}
                  className={`scenario-item ${isThisExecuting ? 'executing' : ''}`}
                >
                  <div className="scenario-header-row">
                    <div>
                      <div className="scenario-codename">{scenario.code}</div>
                      <h2 className="scenario-name">{scenario.name}</h2>
                    </div>
                    <span
                      className={`badge-difficulty ${
                        scenario.difficulty === 'CRITICAL'
                          ? 'critical'
                          : scenario.difficulty === 'HIGH'
                          ? 'high'
                          : 'medium'
                      }`}
                    >
                      {scenario.difficulty}
                    </span>
                  </div>

                  <div className="scenario-vector">
                    <strong>PATHWAY:</strong> {scenario.vector}
                  </div>

                  <p className="scenario-desc">{scenario.description}</p>

                  <div className="techniques-row">
                    {scenario.techniques.map((tech, i) => (
                      <span key={i} className="tech-tag">
                        {tech}
                      </span>
                    ))}
                  </div>

                  <button
                    className="launch-action-btn"
                    disabled={isLaunching}
                    onClick={() => handleLaunchScenario(scenario)}
                  >
                    {isThisExecuting ? (
                      <>
                        <RefreshCw size={13} className="animate-spin" />
                        <span>EXECUTING KILL CHAIN...</span>
                      </>
                    ) : (
                      <>
                        <Crosshair size={13} />
                        <span>LAUNCH ATTACK</span>
                      </>
                    )}
                  </button>
                </div>
              );
            })}
          </div>
        </section>

        {/* Right Column: High-Contrast Monospace Console */}
        <section className="section-panel terminal-card">
          <div className="section-panel-header">
            <div className="section-panel-title">
              <Terminal size={14} color="#00FF66" />
              <span style={{ color: '#00FF66' }}>PAYLOAD CONSOLE</span>
            </div>
            <span className="section-panel-count">{filteredLogs.length} ENTRIES</span>
          </div>

          {/* Filter Bar */}
          <div className="terminal-control-bar">
            <div className="filter-btn-group">
              <button
                className={`filter-btn ${filterMode === 'ALL' ? 'active' : ''}`}
                onClick={() => setFilterMode('ALL')}
              >
                ALL
              </button>
              <button
                className={`filter-btn ${filterMode === 'SUCCESS' ? 'active' : ''}`}
                onClick={() => setFilterMode('SUCCESS')}
              >
                SUCCESS
              </button>
              <button
                className={`filter-btn ${filterMode === 'ERRORS' ? 'active' : ''}`}
                onClick={() => setFilterMode('ERRORS')}
              >
                ERRORS
              </button>
            </div>

            <div className="terminal-actions">
              <button className="action-icon-btn" onClick={handleCopyLogs} title="Copy console text">
                {copied ? <Check size={11} color="#00FF66" /> : <Copy size={11} />}
                <span>{copied ? 'COPIED' : 'COPY'}</span>
              </button>
              <button className="action-icon-btn" onClick={handleClearLogs} title="Clear console">
                <Trash2 size={11} />
                <span>CLEAR</span>
              </button>
            </div>
          </div>

          {/* Scrolling Terminal Viewport */}
          <div className="terminal-viewport">
            {filteredLogs.map((log) => (
              <div key={log.id} className="log-row">
                <span className="log-time">[{log.timestamp}]</span>
                <span className={`log-level-pill ${log.level.toLowerCase()}`}>{log.level}</span>
                <span style={{ color: '#a5b4fc', fontSize: 11, flexShrink: 0 }}>
                  [{log.target}]
                </span>
                <span
                  className={`log-text ${log.isError ? 'error-text' : log.isSuccess ? 'success-text' : ''}`}
                >
                  {log.message}
                </span>
              </div>
            ))}
            <div ref={terminalEndRef} />
          </div>

          {/* Bottom Command Prompt */}
          <div className="terminal-prompt-bar">
            <span className="prompt-user">operator@c2-console:~$</span>
            <span className="prompt-status">
              {isLaunching ? 'transmitting scenario event stream to Port 8000...' : 'idle - awaiting operator action'}
            </span>
            <span className="cursor-blink" />
          </div>
        </section>
      </div>

      {/* ====================================================================
          4. BOTTOM SOC BRIDGE FOOTER: Direct Link to SOC Dashboard
         ==================================================================== */}
      <footer className="soc-bridge-bar">
        <div className="soc-bridge-info">
          <ShieldAlert size={16} color="#00FF66" />
          <span>
            Simulated events populate <code>threat_platform.db</code> in real-time. View generated incidents and attack graph topologies in the SOC Analyst Dashboard:
          </span>
        </div>

        <a
          href="http://localhost:3000/incidents"
          target="_blank"
          rel="noopener noreferrer"
          className="soc-bridge-btn"
        >
          <span>OPEN SOC INCIDENTS PAGE</span>
          <ExternalLink size={13} />
        </a>
      </footer>
    </div>
  );
}
