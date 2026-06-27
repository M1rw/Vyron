import { useState } from 'react'
import {
  Search,
  Moon,
  Sun,
  Bell,
  ChevronDown,
  Store,
  Layers,
  LineChart,
  Route,
  PieChart,
  CalendarClock
} from 'lucide-react'

function App() {
  const [darkMode, setDarkMode] = useState(true)
  const [activeNav, setActiveNav] = useState('overview')
  const [range, setRange] = useState('24h')
  const [filters, setFilters] = useState(['Endpoint: SOC-21', 'OS: Windows', 'Severity: High+', 'Tag: Finance', 'Region: US-East'])
  const [filterSeed, setFilterSeed] = useState(1)
  const [sidebarQuery, setSidebarQuery] = useState('')
  const [globalQuery, setGlobalQuery] = useState('')
  const [lastAction, setLastAction] = useState('')
  const [workspaceMode, setWorkspaceMode] = useState<'Standard' | 'Hardened' | 'Forensics'>('Standard')
  const [autoQuarantine, setAutoQuarantine] = useState(true)
  const [liveIsolation, setLiveIsolation] = useState(false)
  const [retentionDays, setRetentionDays] = useState(30)
  const [alertThreshold, setAlertThreshold] = useState(85)

  const theme = {
    bg: darkMode ? '#0B0C0E' : '#F8FAFC',
    sidebarBg: darkMode ? '#0F0F12' : '#FFFFFF',
    cardBorder: '#2D3139',
    text: darkMode ? '#E6E8ED' : '#0F172A',
    textMuted: darkMode ? '#8B94A3' : '#64748B',
    textDim: darkMode ? '#6B7380' : '#94A3B8',
    accent: '#16A6A1',
    danger: '#EF4444',
    warning: '#F59E0B',
    gold: '#C7A14A',
    blue: '#3B82F6',
    purple: '#8B5CF6',
    panelBg: darkMode ? '#0F1114' : '#FFFFFF',
    panelBorder: '#2D3139',
    gridLine: '#2D3139',
    surface: darkMode ? '#121216' : '#F1F5F9',
    surfaceAlt: darkMode ? '#141418' : '#EEF2F7',
    headerBg: darkMode ? '#0F0F12' : '#FFFFFF',
    kbdBg: darkMode ? '#1A1A20' : '#E2E8F0',
    buttonBg: darkMode ? '#15151B' : '#F1F5F9',
    tableHeaderBg: darkMode ? '#111316' : '#F8FAFC',
    notificationBorder: darkMode ? '#0F0F12' : '#FFFFFF'
  }

  const navItems = [
    { id: 'overview', icon: Store, label: 'Threat Overview' },
    { id: 'detections', icon: Layers, label: 'Detections' },
    { id: 'intel', icon: LineChart, label: 'Intel & Trends' },
    { id: 'hunt', icon: Route, label: 'Hunt Workspace' },
    { id: 'risk', icon: PieChart, label: 'Risk Posture' },
    { id: 'timeline', icon: CalendarClock, label: 'Incident Timeline' }
  ]

  const pageMeta: Record<string, { title: string; subtitle: string; action: string }> = {
    overview: { title: 'Security Console', subtitle: 'SOC Dashboard', action: 'Generate Snapshot' },
    detections: { title: 'Detections', subtitle: 'Active Findings', action: 'Export Findings' },
    intel: { title: 'Intel & Trends', subtitle: 'Threat Intelligence', action: 'Update Feeds' },
    hunt: { title: 'Hunt Workspace', subtitle: 'Live Hunt Sessions', action: 'Run Hunt' },
    risk: { title: 'Risk Posture', subtitle: 'Exposure & Coverage', action: 'Assess Risk' },
    timeline: { title: 'Incident Timeline', subtitle: 'Attack Progression', action: 'Create Case' }
  }

  const currentPage = pageMeta[activeNav] ?? pageMeta.overview

  const detections = [
    { time: '09:42:11', ind: 'PowerShell encoded command', tact: 'Execution', tech: 'T1059', sev: 'High', color: theme.warning },
    { time: '09:38:02', ind: 'Credential dump attempt', tact: 'Credential Access', tech: 'T1003', sev: 'Critical', color: theme.danger },
    { time: '09:31:55', ind: 'Suspicious LOLBin usage', tact: 'Defense Evasion', tech: 'T1218', sev: 'High', color: theme.warning },
    { time: '09:25:19', ind: 'Outbound C2 beacon', tact: 'Command & Control', tech: 'T1071', sev: 'Critical', color: theme.danger }
  ]

  const normalizedQuery = globalQuery.trim().toLowerCase()
  const filteredDetections = normalizedQuery
    ? detections.filter((row) =>
        `${row.time} ${row.ind} ${row.tact} ${row.tech} ${row.sev}`.toLowerCase().includes(normalizedQuery)
      )
    : detections

  const visibleNavItems = sidebarQuery
    ? navItems.filter((item) => item.label.toLowerCase().includes(sidebarQuery.toLowerCase()))
    : navItems

  const drillStyle = {
    fontSize: '10px',
    padding: '2px 6px',
    borderRadius: '6px',
    border: `1px solid ${theme.panelBorder}`,
    color: theme.textDim,
    backgroundColor: theme.surface,
    cursor: 'pointer',
    transition: 'all 120ms ease'
  }

  const recordAction = (label: string) => {
    setLastAction(`${label} • ${new Date().toLocaleTimeString()}`)
  }

  const toggleFilter = (chip: string) => {
    setFilters((prev) => (prev.includes(chip) ? prev.filter((item) => item !== chip) : [...prev, chip]))
  }

  const addFilter = () => {
    const next = `Tag: Ops-${filterSeed}`
    setFilters((prev) => [...prev, next])
    setFilterSeed((prev) => prev + 1)
    recordAction('Filter added')
  }

  const threatsSeries = [48, 36, 29, 42, 55, 64, 58, 71, 83, 79, 92, 108, 97, 120, 114, 138, 128, 149, 139, 165, 154, 182, 171, 198, 190, 214, 206, 238]
  const filesSeries = [62, 41, 35, 54, 66, 71, 60, 78, 89, 83, 101, 118, 109, 132, 126, 149, 138, 160, 151, 178, 168, 196, 187, 210, 201, 228, 219, 248]

  const intelFeed = [
    { source: 'Mandiant', indicator: 'UNC2970 tooling', confidence: 'High', lastSync: '08:12', status: 'Active' },
    { source: 'VirusTotal', indicator: 'Suspicious hash cluster', confidence: 'Medium', lastSync: '08:05', status: 'Active' },
    { source: 'CISA', indicator: 'KEV update', confidence: 'High', lastSync: '07:48', status: 'Queued' }
  ]

  const huntSessions = [
    { name: 'Rundll32 Anomalies', owner: 'A. Chen', scope: 'Endpoints 420', status: 'Running', eta: '12m' },
    { name: 'PowerShell Stagers', owner: 'J. Patel', scope: 'Endpoints 280', status: 'Queued', eta: '21m' },
    { name: 'C2 Beacon Sweep', owner: 'M. Ortiz', scope: 'Network 86', status: 'Running', eta: '8m' }
  ]

  const riskAssets = [
    { asset: 'FIN-DB-07', owner: 'Finance', cvss: '9.1', exposure: 'Public', status: 'Unpatched' },
    { asset: 'HR-APP-02', owner: 'HR', cvss: '8.2', exposure: 'Internal', status: 'Mitigating' },
    { asset: 'CRM-EDGE-01', owner: 'Sales', cvss: '7.8', exposure: 'Public', status: 'Planned' }
  ]

  const timelineEvents = [
    { time: '09:42:11', event: 'PowerShell encoded command', actor: 'SOC-21', status: 'Investigating' },
    { time: '09:38:02', event: 'Credential access attempt', actor: 'EDR', status: 'Contained' },
    { time: '09:31:55', event: 'LOLBin execution', actor: 'Analyst', status: 'Triaged' },
    { time: '09:25:19', event: 'C2 beaconing', actor: 'Network', status: 'Blocked' }
  ]

  const processTree = [
    { name: 'winword.exe', detail: 'Parent • User: j.doe', sev: 'Medium', color: theme.gold, depth: 0 },
    { name: 'powershell.exe', detail: 'Encoded command', sev: 'High', color: theme.warning, depth: 1 },
    { name: 'cmd.exe', detail: 'Stager invoked', sev: 'High', color: theme.warning, depth: 2 },
    { name: 'rundll32.exe', detail: 'DLL sideload', sev: 'Critical', color: theme.danger, depth: 3 },
    { name: 'svchost.exe', detail: 'Persistence attempt', sev: 'Critical', color: theme.danger, depth: 2 }
  ]

  const mitreTactics = ['Initial Access', 'Execution', 'Persistence', 'Privilege Esc.', 'Defense Evasion', 'Credential Access', 'Exfiltration']
  const mitreMatrix = [
    { tech: 'T1059', values: [1, 4, 0, 0, 3, 1, 0] },
    { tech: 'T1003', values: [0, 1, 0, 2, 2, 5, 0] },
    { tech: 'T1218', values: [0, 2, 1, 0, 4, 0, 0] },
    { tech: 'T1071', values: [0, 0, 0, 0, 2, 0, 4] },
    { tech: 'T1547', values: [0, 0, 4, 2, 1, 0, 0] }
  ]

  const heatColor = (level: number) => {
    if (level === 0) return 'transparent'
    const alpha = 0.12 + level * 0.12
    return `rgba(239, 68, 68, ${alpha})`
  }

  const renderPagePanels = () => {
    if (activeNav === 'overview') {
      return (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px', flexWrap: 'wrap' }}>
            {['24h', '7d', '30d', '90d'].map((item) => (
              <button key={item} onClick={() => { setRange(item); recordAction(`Range set to ${item}`) }} style={{ fontSize: '10px', padding: '4px 8px', borderRadius: '6px', border: `1px solid ${theme.panelBorder}`, backgroundColor: range === item ? theme.panelBg : 'transparent', color: range === item ? theme.text : theme.textDim, cursor: 'pointer' }}>{item}</button>
            ))}
            {filters.map((chip) => (
              <button key={chip} onClick={() => toggleFilter(chip)} style={{ fontSize: '10px', padding: '4px 8px', borderRadius: '6px', border: `1px solid ${theme.panelBorder}`, color: theme.textDim, backgroundColor: theme.panelBg, cursor: 'pointer' }}>{chip}</button>
            ))}
            <button onClick={addFilter} style={{ fontSize: '10px', padding: '4px 8px', borderRadius: '6px', border: `1px solid ${theme.panelBorder}`, backgroundColor: theme.panelBg, color: theme.text, cursor: 'pointer' }}>Add Filter</button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px', marginBottom: '8px' }}>
            {[
              { label: 'Critical', value: '6', color: theme.danger },
              { label: 'High', value: '14', color: theme.warning },
              { label: 'Medium', value: '32', color: theme.gold },
              { label: 'Low', value: '87', color: theme.blue },
              { label: 'Investigations', value: '18', color: theme.accent },
              { label: 'Endpoints', value: '1,248', color: theme.purple }
            ].map((item, i) => (
              <div key={i} style={{ gridColumn: 'span 2', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '6px 8px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontSize: '9px', color: theme.textDim, textTransform: 'uppercase', letterSpacing: '0.8px' }}>{item.label}</div>
                  <div style={{ fontSize: '16px', fontWeight: '700', color: item.color, marginTop: '4px' }}>{item.value}</div>
                </div>
                <button onClick={() => recordAction(`${item.label} drill-down`)} style={drillStyle}>Drill</button>
              </div>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px', marginBottom: '8px' }}>
            <div style={{ gridColumn: 'span 7', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <div>
                  <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text }}>Threat Activity</div>
                  <div style={{ fontSize: '10px', color: theme.textDim, fontFamily: "'Roboto Mono', ui-monospace" }}>Events / 24h</div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '10px', color: theme.textDim }}>
                  <span>Detections vs Blocks</span>
                  <button onClick={() => recordAction('Threat activity drill-down')} style={drillStyle}>Drill</button>
                </div>
              </div>
              <svg width="100%" height="160" style={{ overflow: 'visible' }}>
                {[0, 1, 2, 3].map(i => (
                  <line key={i} x1="0" y1={i * 40} x2="100%" y2={i * 40} stroke={theme.gridLine} strokeWidth="1" />
                ))}
                <polyline fill="none" stroke={theme.danger} strokeWidth="2" points={threatsSeries.map((v, i) => `${(i / (threatsSeries.length - 1)) * 100}%,${160 - (v / 260) * 160}`).join(' ')} />
                <polyline fill="none" stroke={theme.warning} strokeWidth="2" points={filesSeries.map((v, i) => `${(i / (filesSeries.length - 1)) * 100}%,${160 - (v / 260) * 160}`).join(' ')} />
              </svg>
              <div style={{ display: 'flex', gap: '12px', marginTop: '6px', fontSize: '10px', color: theme.textDim }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><span style={{ width: '10px', height: '2px', backgroundColor: theme.danger }} /> Critical</span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><span style={{ width: '10px', height: '2px', backgroundColor: theme.warning }} /> High</span>
              </div>
            </div>
            <div style={{ gridColumn: 'span 5', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text }}>MITRE ATT&CK Heatmap</div>
                <button onClick={() => recordAction('MITRE heatmap drill-down')} style={drillStyle}>Drill</button>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: `110px repeat(${mitreTactics.length}, 1fr)`, gap: '4px', fontSize: '9px', color: theme.textDim }}>
                <div />
                {mitreTactics.map((tactic) => (
                  <div key={tactic} style={{ textAlign: 'center', padding: '4px 2px', border: `1px solid ${theme.panelBorder}`, borderRadius: '4px' }}>{tactic}</div>
                ))}
                {mitreMatrix.map((row) => (
                  <div key={row.tech} style={{ display: 'contents' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '4px 6px', border: `1px solid ${theme.panelBorder}`, borderRadius: '4px', color: theme.text, fontSize: '10px' }}>
                      <span style={{ fontFamily: "'Roboto Mono', ui-monospace" }}>{row.tech}</span>
                      <button onClick={() => recordAction(`${row.tech} drill-down`)} style={drillStyle}>Drill</button>
                    </div>
                    {row.values.map((value, idx) => (
                      <div
                        key={`${row.tech}-${idx}`}
                        onClick={() => recordAction(`${row.tech} ${mitreTactics[idx]} drill-down`)}
                        style={{
                          border: `1px solid ${theme.panelBorder}`,
                          borderRadius: '4px',
                          height: '26px',
                          backgroundColor: heatColor(value),
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          cursor: 'pointer',
                          color: theme.text
                        }}
                      >
                        {value > 0 ? value : ''}
                      </div>
                    ))}
                  </div>
                ))}
              </div>
              <div style={{ marginTop: '6px', fontSize: '9px', color: theme.textDim }}>Intensity 0–5 • Click cell to drill.</div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px', marginBottom: '8px' }}>
            <div style={{ gridColumn: 'span 7', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text }}>Process Tree</div>
                <button onClick={() => recordAction('Process tree drill-down')} style={drillStyle}>Drill</button>
              </div>
              <div style={{ display: 'grid', gap: '4px' }}>
                {processTree.map((node, i) => (
                  <div key={`${node.name}-${i}`} style={{ display: 'grid', gridTemplateColumns: '12px 1fr auto auto', alignItems: 'center', gap: '8px', padding: '6px 8px', border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', marginLeft: `${node.depth * 12}px` }}>
                    <div style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: node.color }} />
                    <div>
                      <div style={{ fontSize: '11px', color: theme.text }}>{node.name}</div>
                      <div style={{ fontSize: '10px', color: theme.textDim, fontFamily: "'Roboto Mono', ui-monospace" }}>{node.detail}</div>
                    </div>
                    <span style={{ fontSize: '10px', color: node.color, fontWeight: '600' }}>{node.sev}</span>
                    <button onClick={() => recordAction(`${node.name} drill-down`)} style={drillStyle}>Drill</button>
                  </div>
                ))}
              </div>
              <div style={{ marginTop: '6px', fontSize: '9px', color: theme.textDim }}>Click a node to drill into lineage.</div>
            </div>
            <div style={{ gridColumn: 'span 5', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
              <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '8px' }}>Kill Chain Coverage</div>
              [{
                { label: 'Initial Access', value: 78, color: theme.warning },
                { label: 'Execution', value: 64, color: theme.danger },
                { label: 'Persistence', value: 42, color: theme.gold },
                { label: 'Privilege Escalation', value: 37, color: theme.warning },
                { label: 'Defense Evasion', value: 53, color: theme.danger }
              ].map((row, i) => (
                <div key={i} style={{ marginBottom: i < 4 ? '8px' : 0 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '10px', color: theme.textDim, marginBottom: '4px' }}>
                    <span>{row.label}</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span style={{ color: theme.text }}>{row.value}%</span>
                      <button onClick={() => recordAction(`${row.label} drill-down`)} style={drillStyle}>Drill</button>
                    </div>
                  </div>
                  <div style={{ height: '6px', backgroundColor: theme.gridLine, borderRadius: '4px', overflow: 'hidden' }}>
                    <div style={{ width: `${row.value}%`, height: '100%', backgroundColor: row.color }} />
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px' }}>
            <div style={{ gridColumn: 'span 8', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text }}>Detections (Last {range})</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '10px', color: theme.textDim, fontFamily: "'Roboto Mono', ui-monospace" }}>
                  <span>High+ • Windows • SOC-21</span>
                  <button onClick={() => recordAction('Detections drill-down')} style={drillStyle}>Drill</button>
                </div>
              </div>
              <div style={{ border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', overflow: 'hidden' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr 110px 110px 90px 70px', padding: '8px 10px', backgroundColor: theme.tableHeaderBg, fontSize: '10px', fontWeight: 600, color: theme.textDim, textTransform: 'uppercase', letterSpacing: '0.8px', fontFamily: "'Roboto Mono', ui-monospace" }}>
                  <span>Time</span><span>Indicator</span><span>Tactic</span><span>Technique</span><span>Severity</span><span>Drill</span>
                </div>
                {filteredDetections.length === 0 && (
                  <div style={{ padding: '12px 10px', fontSize: '11px', color: theme.textDim }}>No detections match the current search.</div>
                )}
                {filteredDetections.map((row, i) => (
                  <div key={`${row.time}-${i}`} style={{ display: 'grid', gridTemplateColumns: '120px 1fr 110px 110px 90px 70px', padding: '8px 10px', borderTop: i > 0 ? `1px solid ${theme.panelBorder}` : 'none', fontSize: '11px', lineHeight: '16px', color: theme.textMuted }}>
                    <span style={{ fontFamily: "'Roboto Mono', ui-monospace" }}>{row.time}</span>
                    <span style={{ fontWeight: 500 }}>{row.ind}</span>
                    <span style={{ fontFamily: "'Roboto Mono', ui-monospace" }}>{row.tact}</span>
                    <span style={{ fontFamily: "'Roboto Mono', ui-monospace" }}>{row.tech}</span>
                    <span style={{ color: row.color, fontWeight: 600, fontFamily: "'Roboto Mono', ui-monospace" }}>{row.sev}</span>
                    <button onClick={() => recordAction(`${row.ind} drill-down`)} style={drillStyle}>Drill</button>
                  </div>
                ))}
              </div>
            </div>
            <div style={{ gridColumn: 'span 4', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
              <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '8px' }}>Endpoint Health</div>
              {[
                { label: 'Protected', value: '96%', color: theme.accent },
                { label: 'Needs Patch', value: '3%', color: theme.warning },
                { label: 'Unmanaged', value: '1%', color: theme.danger }
              ].map((item, i) => (
                <div key={i} style={{ marginBottom: i < 2 ? '8px' : 0 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: theme.textDim, marginBottom: '4px' }}>
                    <span>{item.label}</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span style={{ color: theme.text }}>{item.value}</span>
                      <button onClick={() => recordAction(`${item.label} drill-down`)} style={drillStyle}>Drill</button>
                    </div>
                  </div>
                  <div style={{ height: '6px', backgroundColor: theme.gridLine, borderRadius: '4px', overflow: 'hidden' }}>
                    <div style={{ width: item.value, height: '100%', backgroundColor: item.color }} />
                  </div>
                </div>
              ))}
              <div style={{ marginTop: '10px', fontSize: '10px', color: theme.textDim }}>Live refresh enabled.</div>
            </div>
          </div>
        </>
      )
    }

    return (
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px', flexWrap: 'wrap' }}>
          <button onClick={() => recordAction(currentPage.action)} style={{ fontSize: '11px', padding: '6px 10px', borderRadius: '8px', border: `1px solid ${theme.panelBorder}`, backgroundColor: theme.panelBg, color: theme.text, cursor: 'pointer' }}>{currentPage.action}</button>
          <button onClick={() => recordAction('Refresh data')} style={{ fontSize: '11px', padding: '6px 10px', borderRadius: '8px', border: `1px solid ${theme.panelBorder}`, backgroundColor: 'transparent', color: theme.textDim, cursor: 'pointer' }}>Refresh Data</button>
          <button onClick={() => recordAction('Open in workspace')} style={{ fontSize: '11px', padding: '6px 10px', borderRadius: '8px', border: `1px solid ${theme.panelBorder}`, backgroundColor: 'transparent', color: theme.textDim, cursor: 'pointer' }}>Open in Workspace</button>
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '10px', color: theme.textDim }}>
            <span>Mode</span>
            <select value={workspaceMode} onChange={(event) => { setWorkspaceMode(event.target.value as typeof workspaceMode); recordAction(`Mode: ${event.target.value}`) }} style={{ backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, color: theme.text, fontSize: '10px', borderRadius: '6px', padding: '4px 6px' }}>
              <option value="Standard">Standard</option>
              <option value="Hardened">Hardened</option>
              <option value="Forensics">Forensics</option>
            </select>
          </div>
        </div>

        {activeNav === 'detections' && (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px', marginBottom: '8px' }}>
              {[
                { label: 'New Alerts', value: '32', color: theme.warning },
                { label: 'Investigating', value: '11', color: theme.accent },
                { label: 'SLA Breach', value: '3', color: theme.danger }
              ].map((item, i) => (
                <div key={i} style={{ gridColumn: 'span 4', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div>
                    <div style={{ fontSize: '9px', color: theme.textDim, textTransform: 'uppercase', letterSpacing: '0.8px' }}>{item.label}</div>
                    <div style={{ fontSize: '16px', fontWeight: '700', color: item.color, marginTop: '4px' }}>{item.value}</div>
                  </div>
                  <button onClick={() => recordAction(`${item.label} drill-down`)} style={drillStyle}>Drill</button>
                </div>
              ))}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px' }}>
              <div style={{ gridColumn: 'span 8', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text }}>Detections Queue</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '10px', color: theme.textDim, fontFamily: "'Roboto Mono', ui-monospace" }}>
                    <span>Queue: SOC-21</span>
                    <button onClick={() => recordAction('Detections queue drill-down')} style={drillStyle}>Drill</button>
                  </div>
                </div>
                <div style={{ border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', overflow: 'hidden' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '110px 1fr 120px 90px 90px 70px', padding: '8px 10px', backgroundColor: theme.tableHeaderBg, fontSize: '10px', fontWeight: 600, color: theme.textDim, textTransform: 'uppercase', letterSpacing: '0.8px', fontFamily: "'Roboto Mono', ui-monospace" }}>
                    <span>Time</span><span>Indicator</span><span>Host</span><span>Owner</span><span>Severity</span><span>Drill</span>
                  </div>
                  {filteredDetections.map((row, i) => (
                    <div key={`${row.time}-${i}`} style={{ display: 'grid', gridTemplateColumns: '110px 1fr 120px 90px 90px 70px', padding: '8px 10px', borderTop: i > 0 ? `1px solid ${theme.panelBorder}` : 'none', fontSize: '11px', color: theme.textMuted }}>
                      <span style={{ fontFamily: "'Roboto Mono', ui-monospace" }}>{row.time}</span>
                      <span style={{ fontWeight: 500 }}>{row.ind}</span>
                      <span style={{ fontFamily: "'Roboto Mono', ui-monospace" }}>SOC-21</span>
                      <span style={{ fontFamily: "'Roboto Mono', ui-monospace" }}>A. Chen</span>
                      <span style={{ color: row.color, fontWeight: 600, fontFamily: "'Roboto Mono', ui-monospace" }}>{row.sev}</span>
                      <button onClick={() => recordAction(`${row.ind} drill-down`)} style={drillStyle}>Drill</button>
                    </div>
                  ))}
                </div>
              </div>
              <div style={{ gridColumn: 'span 4', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '8px' }}>Case Detail</div>
                <div style={{ display: 'grid', gap: '6px', fontSize: '10px', color: theme.textDim }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Case ID</span><span style={{ color: theme.text }}>VYR-2041</span></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Priority</span><span style={{ color: theme.danger }}>P1</span></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Owner</span><span style={{ color: theme.text }}>A. Chen</span></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Status</span><span style={{ color: theme.warning }}>Investigating</span></div>
                  <button onClick={() => recordAction('Case detail drill-down')} style={drillStyle}>Drill</button>
                </div>
                <div style={{ marginTop: '10px', fontSize: '10px', color: theme.textDim }}>Evidence: 4 artifacts • 2 hosts.</div>
              </div>
            </div>
          </>
        )}

        {activeNav === 'intel' && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px' }}>
            <div style={{ gridColumn: 'span 7', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text }}>Threat Intel Feeds</div>
                <button onClick={() => recordAction('Intel feed drill-down')} style={drillStyle}>Drill</button>
              </div>
              <div style={{ border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', overflow: 'hidden' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr 90px 90px 70px', padding: '8px 10px', backgroundColor: theme.tableHeaderBg, fontSize: '10px', fontWeight: 600, color: theme.textDim, textTransform: 'uppercase', letterSpacing: '0.8px', fontFamily: "'Roboto Mono', ui-monospace" }}>
                  <span>Source</span><span>Indicator</span><span>Confidence</span><span>Last Sync</span><span>Drill</span>
                </div>
                {intelFeed.map((row, i) => (
                  <div key={`${row.source}-${i}`} style={{ display: 'grid', gridTemplateColumns: '120px 1fr 90px 90px 70px', padding: '8px 10px', borderTop: i > 0 ? `1px solid ${theme.panelBorder}` : 'none', fontSize: '11px', color: theme.textMuted }}>
                    <span style={{ fontFamily: "'Roboto Mono', ui-monospace" }}>{row.source}</span>
                    <span>{row.indicator}</span>
                    <span style={{ color: row.confidence === 'High' ? theme.accent : theme.text }}>{row.confidence}</span>
                    <span style={{ fontFamily: "'Roboto Mono', ui-monospace" }}>{row.lastSync}</span>
                    <button onClick={() => recordAction(`${row.source} drill-down`)} style={drillStyle}>Drill</button>
                  </div>
                ))}
              </div>
            </div>
            <div style={{ gridColumn: 'span 5', display: 'grid', gap: '8px' }}>
              <div style={{ backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '6px' }}>Campaign Focus</div>
                {['UNC2970', 'FIN7', 'APT29'].map((campaign) => (
                  <div key={campaign} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '10px', color: theme.textDim, padding: '6px 0', borderTop: `1px solid ${theme.panelBorder}` }}>
                    <span>{campaign}</span>
                    <button onClick={() => recordAction(`${campaign} drill-down`)} style={drillStyle}>Drill</button>
                  </div>
                ))}
              </div>
              <div style={{ backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '6px' }}>Industry Heat</div>
                {['Finance 32%', 'Healthcare 21%', 'Manufacturing 18%'].map((row) => (
                  <div key={row} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: theme.textDim, padding: '4px 0' }}>
                    <span>{row}</span>
                    <button onClick={() => recordAction(`${row} drill-down`)} style={drillStyle}>Drill</button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeNav === 'hunt' && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px' }}>
            <div style={{ gridColumn: 'span 8', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text }}>Active Hunts</div>
                <button onClick={() => recordAction('Hunt sessions drill-down')} style={drillStyle}>Drill</button>
              </div>
              <div style={{ border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', overflow: 'hidden' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 100px 120px 90px 70px', padding: '8px 10px', backgroundColor: theme.tableHeaderBg, fontSize: '10px', fontWeight: 600, color: theme.textDim, textTransform: 'uppercase', letterSpacing: '0.8px', fontFamily: "'Roboto Mono', ui-monospace" }}>
                  <span>Query</span><span>Owner</span><span>Scope</span><span>Status</span><span>Drill</span>
                </div>
                {huntSessions.map((row, i) => (
                  <div key={`${row.name}-${i}`} style={{ display: 'grid', gridTemplateColumns: '1fr 100px 120px 90px 70px', padding: '8px 10px', borderTop: i > 0 ? `1px solid ${theme.panelBorder}` : 'none', fontSize: '11px', color: theme.textMuted }}>
                    <span>{row.name}</span>
                    <span>{row.owner}</span>
                    <span>{row.scope}</span>
                    <span style={{ color: row.status === 'Running' ? theme.accent : theme.textDim }}>{row.status}</span>
                    <button onClick={() => recordAction(`${row.name} drill-down`)} style={drillStyle}>Drill</button>
                  </div>
                ))}
              </div>
            </div>
            <div style={{ gridColumn: 'span 4', display: 'grid', gap: '8px' }}>
              <div style={{ backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '6px' }}>Query Builder</div>
                <div style={{ fontSize: '10px', color: theme.textDim, fontFamily: "'Roboto Mono', ui-monospace" }}>
                  process_name: powershell.exe AND cmdline CONTAINS "-enc"
                </div>
                <button onClick={() => recordAction('Query builder drill-down')} style={{ ...drillStyle, marginTop: '6px' }}>Drill</button>
              </div>
              <div style={{ backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '6px' }}>Telemetry Scope</div>
                {['Endpoints: 684', 'Servers: 214', 'Network: 86'].map((row) => (
                  <div key={row} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: theme.textDim, padding: '4px 0' }}>
                    <span>{row}</span>
                    <button onClick={() => recordAction(`${row} drill-down`)} style={drillStyle}>Drill</button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeNav === 'risk' && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px' }}>
            <div style={{ gridColumn: 'span 7', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text }}>Top Exposed Assets</div>
                <button onClick={() => recordAction('Risk assets drill-down')} style={drillStyle}>Drill</button>
              </div>
              <div style={{ border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', overflow: 'hidden' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 110px 80px 90px 70px', padding: '8px 10px', backgroundColor: theme.tableHeaderBg, fontSize: '10px', fontWeight: 600, color: theme.textDim, textTransform: 'uppercase', letterSpacing: '0.8px', fontFamily: "'Roboto Mono', ui-monospace" }}>
                  <span>Asset</span><span>Owner</span><span>CVSS</span><span>Exposure</span><span>Drill</span>
                </div>
                {riskAssets.map((row, i) => (
                  <div key={`${row.asset}-${i}`} style={{ display: 'grid', gridTemplateColumns: '1fr 110px 80px 90px 70px', padding: '8px 10px', borderTop: i > 0 ? `1px solid ${theme.panelBorder}` : 'none', fontSize: '11px', color: theme.textMuted }}>
                    <span>{row.asset}</span>
                    <span>{row.owner}</span>
                    <span style={{ color: theme.danger }}>{row.cvss}</span>
                    <span>{row.exposure}</span>
                    <button onClick={() => recordAction(`${row.asset} drill-down`)} style={drillStyle}>Drill</button>
                  </div>
                ))}
              </div>
            </div>
            <div style={{ gridColumn: 'span 5', display: 'grid', gap: '8px' }}>
              <div style={{ backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '6px' }}>Coverage Gaps</div>
                {['Legacy OS coverage', 'Email sandbox', 'Cloud audit'].map((row) => (
                  <div key={row} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: theme.textDim, padding: '6px 0', borderTop: `1px solid ${theme.panelBorder}` }}>
                    <span>{row}</span>
                    <button onClick={() => recordAction(`${row} drill-down`)} style={drillStyle}>Drill</button>
                  </div>
                ))}
              </div>
              <div style={{ backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '6px' }}>Control Health</div>
                {['EDR: 96%', 'NDR: 88%', 'Email: 82%'].map((row) => (
                  <div key={row} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: theme.textDim, padding: '4px 0' }}>
                    <span>{row}</span>
                    <button onClick={() => recordAction(`${row} drill-down`)} style={drillStyle}>Drill</button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeNav === 'timeline' && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px' }}>
            <div style={{ gridColumn: 'span 8', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text }}>Incident Timeline</div>
                <button onClick={() => recordAction('Timeline drill-down')} style={drillStyle}>Drill</button>
              </div>
              <div style={{ display: 'grid', gap: '6px' }}>
                {timelineEvents.map((row, i) => (
                  <div key={`${row.time}-${i}`} style={{ display: 'grid', gridTemplateColumns: '90px 1fr 110px 90px 70px', alignItems: 'center', gap: '8px', padding: '6px 8px', border: `1px solid ${theme.panelBorder}`, borderRadius: '6px' }}>
                    <span style={{ fontFamily: "'Roboto Mono', ui-monospace", color: theme.textDim }}>{row.time}</span>
                    <span style={{ fontSize: '11px', color: theme.text }}>{row.event}</span>
                    <span style={{ fontSize: '10px', color: theme.textDim }}>{row.actor}</span>
                    <span style={{ fontSize: '10px', color: theme.textDim }}>{row.status}</span>
                    <button onClick={() => recordAction(`${row.event} drill-down`)} style={drillStyle}>Drill</button>
                  </div>
                ))}
              </div>
            </div>
            <div style={{ gridColumn: 'span 4', display: 'grid', gap: '8px' }}>
              <div style={{ backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '6px' }}>Case Actions</div>
                {['Contain host', 'Preserve memory', 'Notify legal'].map((row) => (
                  <div key={row} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: theme.textDim, padding: '6px 0', borderTop: `1px solid ${theme.panelBorder}` }}>
                    <span>{row}</span>
                    <button onClick={() => recordAction(`${row} drill-down`)} style={drillStyle}>Drill</button>
                  </div>
                ))}
              </div>
              <div style={{ backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '6px' }}>Artifacts</div>
                {['3 memory dumps', '12 IOC hashes', '2 packet captures'].map((row) => (
                  <div key={row} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: theme.textDim, padding: '4px 0' }}>
                    <span>{row}</span>
                    <button onClick={() => recordAction(`${row} drill-down`)} style={drillStyle}>Drill</button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    )
  }

  return (
    <div style={{ minHeight: '100vh', backgroundColor: theme.bg, color: theme.text, fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif", display: 'flex' }}>
      <aside style={{ width: '248px', backgroundColor: theme.sidebarBg, borderRight: `1px solid ${theme.cardBorder}`, display: 'flex', flexDirection: 'column', position: 'fixed', left: 0, top: 0, bottom: 0, zIndex: 100, padding: '18px 14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '6px 6px 18px' }}>
          <div style={{ width: '34px', height: '34px', borderRadius: '10px', background: `linear-gradient(135deg, ${theme.accent}, #0E8D8A)`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '14px', fontWeight: '700', color: '#fff', flexShrink: 0 }}>V</div>
          <div style={{ overflow: 'hidden' }}>
            <div style={{ fontSize: '15px', fontWeight: '700', color: theme.text, letterSpacing: '-0.3px' }}>Vyron</div>
            <div style={{ fontSize: '10px', color: theme.textMuted, textTransform: 'uppercase', letterSpacing: '0.6px' }}>Security</div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', backgroundColor: theme.surface, border: `1px solid ${theme.cardBorder}`, borderRadius: '12px', padding: '6px 10px', height: '36px', marginBottom: '14px' }}>
          <Search size={14} color={theme.textDim} />
          <input type="text" placeholder="Search Vyron" value={sidebarQuery} onChange={(event) => setSidebarQuery(event.target.value)} style={{ border: 'none', background: 'transparent', outline: 'none', fontSize: '12px', color: theme.text, width: '100%', fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif" }} />
          <kbd style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', height: '18px', minWidth: '34px', padding: '0 8px', fontSize: '10px', fontWeight: 600, lineHeight: '18px', letterSpacing: '0.3px', fontFamily: "'Roboto Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace", whiteSpace: 'nowrap', textAlign: 'center', backgroundColor: theme.kbdBg, borderRadius: '6px', color: theme.textDim, border: `1px solid ${theme.cardBorder}` }}>⌘ K</kbd>
        </div>

        <div style={{ padding: '2px 6px 8px', fontSize: '9px', fontWeight: 600, color: theme.textDim, textTransform: 'uppercase', letterSpacing: '1.6px', fontFamily: "'Roboto Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace" }}>Navigation</div>

        <nav style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '4px' }}>
          {visibleNavItems.length === 0 && (
            <div style={{ padding: '8px 10px', fontSize: '11px', color: theme.textDim }}>No matches</div>
          )}
          {visibleNavItems.map((item) => (
            <button key={item.id} onClick={() => { setActiveNav(item.id); recordAction(`Open ${item.label}`) }} style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 10px', borderRadius: '9px', backgroundColor: activeNav === item.id ? theme.surfaceAlt : 'transparent', border: activeNav === item.id ? `1px solid ${theme.cardBorder}` : '1px solid transparent', color: activeNav === item.id ? theme.text : theme.textMuted, cursor: 'pointer', transition: 'all 0.2s ease', width: '100%', justifyContent: 'flex-start' }}>
              <item.icon size={15} strokeWidth={1.6} />
              <span style={{ fontSize: '12px', fontWeight: 500, letterSpacing: '0.2px', whiteSpace: 'nowrap' }}>{item.label}</span>
            </button>
          ))}
        </nav>
      </aside>

      <main style={{ flex: 1, marginLeft: '248px' }}>
        <header style={{ height: '64px', backgroundColor: theme.headerBg, borderBottom: `1px solid ${theme.panelBorder}`, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px', position: 'sticky', top: 0, zIndex: 50 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div style={{ fontSize: '12px', letterSpacing: '1.2px', color: theme.textDim, textTransform: 'uppercase' }}>Vyron SOC</div>
            <div style={{ width: '1px', height: '18px', backgroundColor: theme.panelBorder }} />
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', backgroundColor: theme.surface, border: `1px solid ${theme.panelBorder}`, borderRadius: '12px', padding: '8px 12px', width: '380px' }}>
              <Search size={16} color={theme.textDim} />
              <input type="text" placeholder="Search threats, files, endpoints..." value={globalQuery} onChange={(event) => setGlobalQuery(event.target.value)} style={{ border: 'none', background: 'transparent', outline: 'none', fontSize: '13px', color: theme.text, width: '100%', fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif" }} />
              <kbd style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', height: '20px', minWidth: '52px', padding: '0 8px', fontSize: '10px', fontWeight: 600, lineHeight: '20px', letterSpacing: '0.3px', fontFamily: "'Roboto Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace", whiteSpace: 'nowrap', textAlign: 'center', backgroundColor: theme.kbdBg, borderRadius: '6px', color: theme.textDim, border: `1px solid ${theme.panelBorder}` }}>Ctrl+K</kbd>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button onClick={() => setDarkMode(!darkMode)} style={{ width: '36px', height: '36px', borderRadius: '10px', backgroundColor: theme.buttonBg, border: `1px solid ${theme.panelBorder}`, color: theme.textMuted, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{darkMode ? <Sun size={16} /> : <Moon size={16} />}</button>
            <button style={{ width: '36px', height: '36px', borderRadius: '10px', backgroundColor: theme.buttonBg, border: `1px solid ${theme.panelBorder}`, color: theme.textMuted, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative' }}><Bell size={16} /><div style={{ position: 'absolute', top: '7px', right: '7px', width: '7px', height: '7px', backgroundColor: theme.danger, borderRadius: '50%', border: `2px solid ${theme.notificationBorder}` }} /></button>
            <div style={{ width: '1px', height: '22px', backgroundColor: theme.panelBorder, margin: '0 6px' }} />
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
              <div style={{ width: '34px', height: '34px', borderRadius: '10px', background: 'linear-gradient(135deg, #6366F1, #8B5CF6)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', fontWeight: '600', color: '#fff' }}>AD</div>
              <div><div style={{ fontSize: '13px', fontWeight: '600', color: theme.text }}>Admin User</div><div style={{ fontSize: '11px', color: theme.textDim }}>admin@vyron.io</div></div>
              <ChevronDown size={14} color={theme.textMuted} />
            </div>
          </div>
        </header>

        <div style={{ padding: '16px 22px 24px', backgroundColor: theme.bg }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
            <div>
              <div style={{ fontSize: '11px', color: theme.textDim, letterSpacing: '1.4px', textTransform: 'uppercase' }}>{currentPage.subtitle}</div>
              <div style={{ fontSize: '18px', fontWeight: '700', color: theme.text }}>{currentPage.title}</div>
              {lastAction && <div style={{ marginTop: '4px', fontSize: '10px', color: theme.textDim }}>{lastAction}</div>}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '11px', color: theme.textDim, fontFamily: "'Roboto Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace" }}>
              <span>Live</span>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: theme.accent }} />
              <span>Refresh 15s</span>
              <span style={{ border: `1px solid ${theme.panelBorder}`, padding: '4px 6px', borderRadius: '6px', backgroundColor: theme.panelBg }}>UTC</span>
            </div>
          </div>

          {renderPagePanels()}
        </div>
      </main>
    </div>
  )
}

export default App

/*
import { useState } from 'react'
import {
  Search,
  Moon,
  Sun,
  Bell,
  ChevronDown,
  Store,
  Layers,
  LineChart,
  Route,
  PieChart,
  CalendarClock
} from 'lucide-react'

function App() {
  const [darkMode, setDarkMode] = useState(true)
  const [activeNav, setActiveNav] = useState('overview')
  const [range, setRange] = useState('24h')
  const [filters, setFilters] = useState(['Endpoint: SOC-21', 'OS: Windows', 'Severity: High+', 'Tag: Finance', 'Region: US-East'])
  const [filterSeed, setFilterSeed] = useState(1)
  const [sidebarQuery, setSidebarQuery] = useState('')
  const [globalQuery, setGlobalQuery] = useState('')
  const [lastAction, setLastAction] = useState('')
  const [workspaceMode, setWorkspaceMode] = useState<'Standard' | 'Hardened' | 'Forensics'>('Standard')
  const [autoQuarantine, setAutoQuarantine] = useState(true)
  const [liveIsolation, setLiveIsolation] = useState(false)
  const [retentionDays, setRetentionDays] = useState(30)
  const [alertThreshold, setAlertThreshold] = useState(85)

  const theme = {
    bg: darkMode ? '#0B0C0E' : '#F8FAFC',
    sidebarBg: darkMode ? '#0F0F12' : '#FFFFFF',
    cardBorder: '#2D3139',
    text: darkMode ? '#E6E8ED' : '#0F172A',
    textMuted: darkMode ? '#8B94A3' : '#64748B',
    textDim: darkMode ? '#6B7380' : '#94A3B8',
    accent: '#16A6A1',
    danger: '#EF4444',
    warning: '#F59E0B',
    gold: '#C7A14A',
    blue: '#3B82F6',
    purple: '#8B5CF6',
    panelBg: darkMode ? '#0F1114' : '#FFFFFF',
    panelBorder: '#2D3139',
    gridLine: '#2D3139',
    surface: darkMode ? '#121216' : '#F1F5F9',
    surfaceAlt: darkMode ? '#141418' : '#EEF2F7',
    headerBg: darkMode ? '#0F0F12' : '#FFFFFF',
    kbdBg: darkMode ? '#1A1A20' : '#E2E8F0',
    buttonBg: darkMode ? '#15151B' : '#F1F5F9',
    tableHeaderBg: darkMode ? '#111316' : '#F8FAFC',
    notificationBorder: darkMode ? '#0F0F12' : '#FFFFFF'
  }

  const navItems = [
    { id: 'overview', icon: Store, label: 'Threat Overview' },
    { id: 'detections', icon: Layers, label: 'Detections' },
    { id: 'intel', icon: LineChart, label: 'Intel & Trends' },
    { id: 'hunt', icon: Route, label: 'Hunt Workspace' },
    { id: 'risk', icon: PieChart, label: 'Risk Posture' },
    { id: 'timeline', icon: CalendarClock, label: 'Incident Timeline' }
  ]

  const pageMeta: Record<string, { title: string; subtitle: string; action: string }> = {
    overview: { title: 'Security Console', subtitle: 'SOC Dashboard', action: 'Generate Snapshot' },
    detections: { title: 'Detections', subtitle: 'Active Findings', action: 'Export Findings' },
    intel: { title: 'Intel & Trends', subtitle: 'Threat Intelligence', action: 'Update Feeds' },
    hunt: { title: 'Hunt Workspace', subtitle: 'Live Hunt Sessions', action: 'Run Hunt' },
    risk: { title: 'Risk Posture', subtitle: 'Exposure & Coverage', action: 'Assess Risk' },
    timeline: { title: 'Incident Timeline', subtitle: 'Attack Progression', action: 'Create Case' }
  }

  const currentPage = pageMeta[activeNav] ?? pageMeta.overview

  const detections = [
    { time: '09:42:11', ind: 'PowerShell encoded command', tact: 'Execution', tech: 'T1059', sev: 'High', color: theme.warning },
    { time: '09:38:02', ind: 'Credential dump attempt', tact: 'Credential Access', tech: 'T1003', sev: 'Critical', color: theme.danger },
    { time: '09:31:55', ind: 'Suspicious LOLBin usage', tact: 'Defense Evasion', tech: 'T1218', sev: 'High', color: theme.warning },
    { time: '09:25:19', ind: 'Outbound C2 beacon', tact: 'Command & Control', tech: 'T1071', sev: 'Critical', color: theme.danger }
  ]

  const normalizedQuery = globalQuery.trim().toLowerCase()
  const filteredDetections = normalizedQuery
    ? detections.filter((row) =>
        `${row.time} ${row.ind} ${row.tact} ${row.tech} ${row.sev}`.toLowerCase().includes(normalizedQuery)
      )
    : detections

  const visibleNavItems = sidebarQuery
    ? navItems.filter((item) => item.label.toLowerCase().includes(sidebarQuery.toLowerCase()))
    : navItems

  const drillStyle = {
    fontSize: '10px',
    padding: '2px 6px',
    borderRadius: '6px',
    border: `1px solid ${theme.panelBorder}`,
    color: theme.textDim,
    backgroundColor: theme.surface,
    cursor: 'pointer',
    transition: 'all 120ms ease'
  }

  const recordAction = (label: string) => {
    setLastAction(`${label} • ${new Date().toLocaleTimeString()}`)
  }
  const toggleFilter = (chip: string) => {
    setFilters((prev) => (prev.includes(chip) ? prev.filter((item) => item !== chip) : [...prev, chip]))
  }

  const addFilter = () => {
    const next = `Tag: Ops-${filterSeed}`
    setFilters((prev) => [...prev, next])
    setFilterSeed((prev) => prev + 1)
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px', marginBottom: '8px' }}>
            <div style={{ gridColumn: 'span 7', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                import { useState } from 'react'
                import {
                  Search,
                  Moon,
                  Sun,
                  Bell,
                  ChevronDown,
                  Store,
                  Layers,
                  LineChart,
                  Route,
                  PieChart,
                  CalendarClock
                } from 'lucide-react'

                function App() {
                  const [darkMode, setDarkMode] = useState(true)
                  const [activeNav, setActiveNav] = useState('overview')
                  const [range, setRange] = useState('24h')
                  const [filters, setFilters] = useState(['Endpoint: SOC-21', 'OS: Windows', 'Severity: High+', 'Tag: Finance', 'Region: US-East'])
                  const [filterSeed, setFilterSeed] = useState(1)
                  const [sidebarQuery, setSidebarQuery] = useState('')
                  const [globalQuery, setGlobalQuery] = useState('')
                  const [lastAction, setLastAction] = useState('')
                  const [workspaceMode, setWorkspaceMode] = useState<'Standard' | 'Hardened' | 'Forensics'>('Standard')
                  const [autoQuarantine, setAutoQuarantine] = useState(true)
                  const [liveIsolation, setLiveIsolation] = useState(false)
                  const [retentionDays, setRetentionDays] = useState(30)
                  const [alertThreshold, setAlertThreshold] = useState(85)

                  const theme = {
                    bg: darkMode ? '#0B0C0E' : '#F8FAFC',
                    sidebarBg: darkMode ? '#0F0F12' : '#FFFFFF',
                    cardBorder: '#2D3139',
                    text: darkMode ? '#E6E8ED' : '#0F172A',
                    textMuted: darkMode ? '#8B94A3' : '#64748B',
                    textDim: darkMode ? '#6B7380' : '#94A3B8',
                    accent: '#16A6A1',
                    danger: '#EF4444',
                    warning: '#F59E0B',
                    gold: '#C7A14A',
                    blue: '#3B82F6',
                    purple: '#8B5CF6',
                    panelBg: darkMode ? '#0F1114' : '#FFFFFF',
                    panelBorder: '#2D3139',
                    gridLine: '#2D3139',
                    surface: darkMode ? '#121216' : '#F1F5F9',
                    surfaceAlt: darkMode ? '#141418' : '#EEF2F7',
                    headerBg: darkMode ? '#0F0F12' : '#FFFFFF',
                    kbdBg: darkMode ? '#1A1A20' : '#E2E8F0',
                    buttonBg: darkMode ? '#15151B' : '#F1F5F9',
                    tableHeaderBg: darkMode ? '#111316' : '#F8FAFC',
                    notificationBorder: darkMode ? '#0F0F12' : '#FFFFFF'
                  }

                  const navItems = [
                    { id: 'overview', icon: Store, label: 'Threat Overview' },
                    { id: 'detections', icon: Layers, label: 'Detections' },
                    { id: 'intel', icon: LineChart, label: 'Intel & Trends' },
                    { id: 'hunt', icon: Route, label: 'Hunt Workspace' },
                    { id: 'risk', icon: PieChart, label: 'Risk Posture' },
                    { id: 'timeline', icon: CalendarClock, label: 'Incident Timeline' }
                  ]

                  const pageMeta: Record<string, { title: string; subtitle: string; action: string }> = {
                    overview: { title: 'Security Console', subtitle: 'SOC Dashboard', action: 'Generate Snapshot' },
                    detections: { title: 'Detections', subtitle: 'Active Findings', action: 'Export Findings' },
                    intel: { title: 'Intel & Trends', subtitle: 'Threat Intelligence', action: 'Update Feeds' },
                    hunt: { title: 'Hunt Workspace', subtitle: 'Live Hunt Sessions', action: 'Run Hunt' },
                    risk: { title: 'Risk Posture', subtitle: 'Exposure & Coverage', action: 'Assess Risk' },
                    timeline: { title: 'Incident Timeline', subtitle: 'Attack Progression', action: 'Create Case' }
                  }

                  const currentPage = pageMeta[activeNav] ?? pageMeta.overview

                  const detections = [
                    { time: '09:42:11', ind: 'PowerShell encoded command', tact: 'Execution', tech: 'T1059', sev: 'High', color: theme.warning },
                    { time: '09:38:02', ind: 'Credential dump attempt', tact: 'Credential Access', tech: 'T1003', sev: 'Critical', color: theme.danger },
                    { time: '09:31:55', ind: 'Suspicious LOLBin usage', tact: 'Defense Evasion', tech: 'T1218', sev: 'High', color: theme.warning },
                    { time: '09:25:19', ind: 'Outbound C2 beacon', tact: 'Command & Control', tech: 'T1071', sev: 'Critical', color: theme.danger }
                  ]

                  const normalizedQuery = globalQuery.trim().toLowerCase()
                  const filteredDetections = normalizedQuery
                    ? detections.filter((row) =>
                        `${row.time} ${row.ind} ${row.tact} ${row.tech} ${row.sev}`.toLowerCase().includes(normalizedQuery)
                      )
                    : detections

                  const visibleNavItems = sidebarQuery
                    ? navItems.filter((item) => item.label.toLowerCase().includes(sidebarQuery.toLowerCase()))
                    : navItems

                  const drillStyle = {
                    fontSize: '10px',
                    padding: '2px 6px',
                    borderRadius: '6px',
                    border: `1px solid ${theme.panelBorder}`,
                    color: theme.textDim,
                    backgroundColor: theme.surface,
                    cursor: 'pointer',
                    transition: 'all 120ms ease'
                  }

                  const recordAction = (label: string) => {
                    setLastAction(`${label} • ${new Date().toLocaleTimeString()}`)
                  }

                  const toggleFilter = (chip: string) => {
                    setFilters((prev) => (prev.includes(chip) ? prev.filter((item) => item !== chip) : [...prev, chip]))
                  }

                  const addFilter = () => {
                    const next = `Tag: Ops-${filterSeed}`
                    setFilters((prev) => [...prev, next])
                    setFilterSeed((prev) => prev + 1)
                    recordAction('Filter added')
                  }

                  const threatsSeries = [48, 36, 29, 42, 55, 64, 58, 71, 83, 79, 92, 108, 97, 120, 114, 138, 128, 149, 139, 165, 154, 182, 171, 198, 190, 214, 206, 238]
                  const filesSeries = [62, 41, 35, 54, 66, 71, 60, 78, 89, 83, 101, 118, 109, 132, 126, 149, 138, 160, 151, 178, 168, 196, 187, 210, 201, 228, 219, 248]

                  const intelFeed = [
                    { source: 'Mandiant', indicator: 'UNC2970 tooling', confidence: 'High', lastSync: '08:12', status: 'Active' },
                    { source: 'VirusTotal', indicator: 'Suspicious hash cluster', confidence: 'Medium', lastSync: '08:05', status: 'Active' },
                    { source: 'CISA', indicator: 'KEV update', confidence: 'High', lastSync: '07:48', status: 'Queued' }
                  ]

                  const huntSessions = [
                    { name: 'Rundll32 Anomalies', owner: 'A. Chen', scope: 'Endpoints 420', status: 'Running', eta: '12m' },
                    { name: 'PowerShell Stagers', owner: 'J. Patel', scope: 'Endpoints 280', status: 'Queued', eta: '21m' },
                    { name: 'C2 Beacon Sweep', owner: 'M. Ortiz', scope: 'Network 86', status: 'Running', eta: '8m' }
                  ]

                  const riskAssets = [
                    { asset: 'FIN-DB-07', owner: 'Finance', cvss: '9.1', exposure: 'Public', status: 'Unpatched' },
                    { asset: 'HR-APP-02', owner: 'HR', cvss: '8.2', exposure: 'Internal', status: 'Mitigating' },
                    { asset: 'CRM-EDGE-01', owner: 'Sales', cvss: '7.8', exposure: 'Public', status: 'Planned' }
                  ]

                  const timelineEvents = [
                    { time: '09:42:11', event: 'PowerShell encoded command', actor: 'SOC-21', status: 'Investigating' },
                    { time: '09:38:02', event: 'Credential access attempt', actor: 'EDR', status: 'Contained' },
                    { time: '09:31:55', event: 'LOLBin execution', actor: 'Analyst', status: 'Triaged' },
                    { time: '09:25:19', event: 'C2 beaconing', actor: 'Network', status: 'Blocked' }
                  ]

                  const processTree = [
                    { name: 'winword.exe', detail: 'Parent • User: j.doe', sev: 'Medium', color: theme.gold, depth: 0 },
                    { name: 'powershell.exe', detail: 'Encoded command', sev: 'High', color: theme.warning, depth: 1 },
                    { name: 'cmd.exe', detail: 'Stager invoked', sev: 'High', color: theme.warning, depth: 2 },
                    { name: 'rundll32.exe', detail: 'DLL sideload', sev: 'Critical', color: theme.danger, depth: 3 },
                    { name: 'svchost.exe', detail: 'Persistence attempt', sev: 'Critical', color: theme.danger, depth: 2 }
                  ]

                  const mitreTactics = ['Initial Access', 'Execution', 'Persistence', 'Privilege Esc.', 'Defense Evasion', 'Credential Access', 'Exfiltration']
                  const mitreMatrix = [
                    { tech: 'T1059', values: [1, 4, 0, 0, 3, 1, 0] },
                    { tech: 'T1003', values: [0, 1, 0, 2, 2, 5, 0] },
                    { tech: 'T1218', values: [0, 2, 1, 0, 4, 0, 0] },
                    { tech: 'T1071', values: [0, 0, 0, 0, 2, 0, 4] },
                    { tech: 'T1547', values: [0, 0, 4, 2, 1, 0, 0] }
                  ]

                  const heatColor = (level: number) => {
                    if (level === 0) return 'transparent'
                    const alpha = 0.12 + level * 0.12
                    return `rgba(239, 68, 68, ${alpha})`
                  }

                  const renderPagePanels = () => {
                    if (activeNav === 'overview') {
                      return (
                        <>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px', flexWrap: 'wrap' }}>
                            {['24h', '7d', '30d', '90d'].map((item) => (
                              <button key={item} onClick={() => { setRange(item); recordAction(`Range set to ${item}`) }} style={{ fontSize: '10px', padding: '4px 8px', borderRadius: '6px', border: `1px solid ${theme.panelBorder}`, backgroundColor: range === item ? theme.panelBg : 'transparent', color: range === item ? theme.text : theme.textDim, cursor: 'pointer' }}>{item}</button>
                            ))}
                            {filters.map((chip) => (
                              <button key={chip} onClick={() => toggleFilter(chip)} style={{ fontSize: '10px', padding: '4px 8px', borderRadius: '6px', border: `1px solid ${theme.panelBorder}`, color: theme.textDim, backgroundColor: theme.panelBg, cursor: 'pointer' }}>{chip}</button>
                            ))}
                            <button onClick={addFilter} style={{ fontSize: '10px', padding: '4px 8px', borderRadius: '6px', border: `1px solid ${theme.panelBorder}`, backgroundColor: theme.panelBg, color: theme.text, cursor: 'pointer' }}>Add Filter</button>
                          </div>

                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px', marginBottom: '8px' }}>
                            [
                              { label: 'Critical', value: '6', color: theme.danger },
                              { label: 'High', value: '14', color: theme.warning },
                              { label: 'Medium', value: '32', color: theme.gold },
                              { label: 'Low', value: '87', color: theme.blue },
                              { label: 'Investigations', value: '18', color: theme.accent },
                              { label: 'Endpoints', value: '1,248', color: theme.purple }
                            ].map((item, i) => (
                              <div key={i} style={{ gridColumn: 'span 2', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '6px 8px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <div>
                                  <div style={{ fontSize: '9px', color: theme.textDim, textTransform: 'uppercase', letterSpacing: '0.8px' }}>{item.label}</div>
                                  <div style={{ fontSize: '16px', fontWeight: '700', color: item.color, marginTop: '4px' }}>{item.value}</div>
                                </div>
                                <button onClick={() => recordAction(`${item.label} drill-down`)} style={drillStyle}>Drill</button>
                              </div>
                            ))}
                          </div>

                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px', marginBottom: '8px' }}>
                            <div style={{ gridColumn: 'span 7', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                                <div>
                                  <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text }}>Threat Activity</div>
                                  <div style={{ fontSize: '10px', color: theme.textDim, fontFamily: "'Roboto Mono', ui-monospace" }}>Events / 24h</div>
                                </div>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '10px', color: theme.textDim }}>
                                  <span>Detections vs Blocks</span>
                                  <button onClick={() => recordAction('Threat activity drill-down')} style={drillStyle}>Drill</button>
                                </div>
                              </div>
                              <svg width="100%" height="160" style={{ overflow: 'visible' }}>
                                {[0, 1, 2, 3].map(i => (
                                  <line key={i} x1="0" y1={i * 40} x2="100%" y2={i * 40} stroke={theme.gridLine} strokeWidth="1" />
                                ))}
                                <polyline fill="none" stroke={theme.danger} strokeWidth="2" points={threatsSeries.map((v, i) => `${(i / (threatsSeries.length - 1)) * 100}%,${160 - (v / 260) * 160}`).join(' ')} />
                                <polyline fill="none" stroke={theme.warning} strokeWidth="2" points={filesSeries.map((v, i) => `${(i / (filesSeries.length - 1)) * 100}%,${160 - (v / 260) * 160}`).join(' ')} />
                              </svg>
                              <div style={{ display: 'flex', gap: '12px', marginTop: '6px', fontSize: '10px', color: theme.textDim }}>
                                <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><span style={{ width: '10px', height: '2px', backgroundColor: theme.danger }} /> Critical</span>
                                <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><span style={{ width: '10px', height: '2px', backgroundColor: theme.warning }} /> High</span>
                              </div>
                            </div>
                            <div style={{ gridColumn: 'span 5', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text }}>MITRE ATT&CK Heatmap</div>
                                <button onClick={() => recordAction('MITRE heatmap drill-down')} style={drillStyle}>Drill</button>
                              </div>
                              <div style={{ display: 'grid', gridTemplateColumns: `110px repeat(${mitreTactics.length}, 1fr)`, gap: '4px', fontSize: '9px', color: theme.textDim }}>
                                <div />
                                {mitreTactics.map((tactic) => (
                                  <div key={tactic} style={{ textAlign: 'center', padding: '4px 2px', border: `1px solid ${theme.panelBorder}`, borderRadius: '4px' }}>{tactic}</div>
                                ))}
                                {mitreMatrix.map((row) => (
                                  <div key={row.tech} style={{ display: 'contents' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '4px 6px', border: `1px solid ${theme.panelBorder}`, borderRadius: '4px', color: theme.text, fontSize: '10px' }}>
                                      <span style={{ fontFamily: "'Roboto Mono', ui-monospace" }}>{row.tech}</span>
                                      <button onClick={() => recordAction(`${row.tech} drill-down`)} style={drillStyle}>Drill</button>
                                    </div>
                                    {row.values.map((value, idx) => (
                                      <div
                                        key={`${row.tech}-${idx}`}
                                        onClick={() => recordAction(`${row.tech} ${mitreTactics[idx]} drill-down`)}
                                        style={{
                                          border: `1px solid ${theme.panelBorder}`,
                                          borderRadius: '4px',
                                          height: '26px',
                                          backgroundColor: heatColor(value),
                                          display: 'flex',
                                          alignItems: 'center',
                                          justifyContent: 'center',
                                          cursor: 'pointer',
                                          color: theme.text
                                        }}
                                      >
                                        {value > 0 ? value : ''}
                                      </div>
                                    ))}
                                  </div>
                                ))}
                              </div>
                              <div style={{ marginTop: '6px', fontSize: '9px', color: theme.textDim }}>Intensity 0–5 • Click cell to drill.</div>
                            </div>
                          </div>

                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px', marginBottom: '8px' }}>
                            <div style={{ gridColumn: 'span 7', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text }}>Process Tree</div>
                                <button onClick={() => recordAction('Process tree drill-down')} style={drillStyle}>Drill</button>
                              </div>
                              <div style={{ display: 'grid', gap: '4px' }}>
                                {processTree.map((node, i) => (
                                  <div key={`${node.name}-${i}`} style={{ display: 'grid', gridTemplateColumns: '12px 1fr auto auto', alignItems: 'center', gap: '8px', padding: '6px 8px', border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', marginLeft: `${node.depth * 12}px` }}>
                                    <div style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: node.color }} />
                                    <div>
                                      <div style={{ fontSize: '11px', color: theme.text }}>{node.name}</div>
                                      <div style={{ fontSize: '10px', color: theme.textDim, fontFamily: "'Roboto Mono', ui-monospace" }}>{node.detail}</div>
                                    </div>
                                    <span style={{ fontSize: '10px', color: node.color, fontWeight: '600' }}>{node.sev}</span>
                                    <button onClick={() => recordAction(`${node.name} drill-down`)} style={drillStyle}>Drill</button>
                                  </div>
                                ))}
                              </div>
                              <div style={{ marginTop: '6px', fontSize: '9px', color: theme.textDim }}>Click a node to drill into lineage.</div>
                            </div>
                            <div style={{ gridColumn: 'span 5', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                              <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '8px' }}>Kill Chain Coverage</div>
                              {[
                                { label: 'Initial Access', value: 78, color: theme.warning },
                                { label: 'Execution', value: 64, color: theme.danger },
                                { label: 'Persistence', value: 42, color: theme.gold },
                                { label: 'Privilege Escalation', value: 37, color: theme.warning },
                                { label: 'Defense Evasion', value: 53, color: theme.danger }
                              ].map((row, i) => (
                                <div key={i} style={{ marginBottom: i < 4 ? '8px' : 0 }}>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '10px', color: theme.textDim, marginBottom: '4px' }}>
                                    <span>{row.label}</span>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                      <span style={{ color: theme.text }}>{row.value}%</span>
                                      <button onClick={() => recordAction(`${row.label} drill-down`)} style={drillStyle}>Drill</button>
                                    </div>
                                  </div>
                                  <div style={{ height: '6px', backgroundColor: theme.gridLine, borderRadius: '4px', overflow: 'hidden' }}>
                                    <div style={{ width: `${row.value}%`, height: '100%', backgroundColor: row.color }} />
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>

                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px' }}>
                            <div style={{ gridColumn: 'span 8', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text }}>Detections (Last {range})</div>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '10px', color: theme.textDim, fontFamily: "'Roboto Mono', ui-monospace" }}>
                                  <span>High+ • Windows • SOC-21</span>
                                  <button onClick={() => recordAction('Detections drill-down')} style={drillStyle}>Drill</button>
                                </div>
                              </div>
                              <div style={{ border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', overflow: 'hidden' }}>
                                <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr 110px 110px 90px 70px', padding: '8px 10px', backgroundColor: theme.tableHeaderBg, fontSize: '10px', fontWeight: 600, color: theme.textDim, textTransform: 'uppercase', letterSpacing: '0.8px', fontFamily: "'Roboto Mono', ui-monospace" }}>
                                  <span>Time</span><span>Indicator</span><span>Tactic</span><span>Technique</span><span>Severity</span><span>Drill</span>
                                </div>
                                {filteredDetections.length === 0 && (
                                  <div style={{ padding: '12px 10px', fontSize: '11px', color: theme.textDim }}>No detections match the current search.</div>
                                )}
                                {filteredDetections.map((row, i) => (
                                  <div key={`${row.time}-${i}`} style={{ display: 'grid', gridTemplateColumns: '120px 1fr 110px 110px 90px 70px', padding: '8px 10px', borderTop: i > 0 ? `1px solid ${theme.panelBorder}` : 'none', fontSize: '11px', lineHeight: '16px', color: theme.textMuted }}>
                                    <span style={{ fontFamily: "'Roboto Mono', ui-monospace" }}>{row.time}</span>
                                    <span style={{ fontWeight: 500 }}>{row.ind}</span>
                                    <span style={{ fontFamily: "'Roboto Mono', ui-monospace" }}>{row.tact}</span>
                                    <span style={{ fontFamily: "'Roboto Mono', ui-monospace" }}>{row.tech}</span>
                                    <span style={{ color: row.color, fontWeight: 600, fontFamily: "'Roboto Mono', ui-monospace" }}>{row.sev}</span>
                                    <button onClick={() => recordAction(`${row.ind} drill-down`)} style={drillStyle}>Drill</button>
                                  </div>
                                ))}
                              </div>
                            </div>
                            <div style={{ gridColumn: 'span 4', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                              <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '8px' }}>Endpoint Health</div>
                              [{
                                { label: 'Protected', value: '96%', color: theme.accent },
                                { label: 'Needs Patch', value: '3%', color: theme.warning },
                                { label: 'Unmanaged', value: '1%', color: theme.danger }
                              ].map((item, i) => (
                                <div key={i} style={{ marginBottom: i < 2 ? '8px' : 0 }}>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: theme.textDim, marginBottom: '4px' }}>
                                    <span>{item.label}</span>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                      <span style={{ color: theme.text }}>{item.value}</span>
                                      <button onClick={() => recordAction(`${item.label} drill-down`)} style={drillStyle}>Drill</button>
                                    </div>
                                  </div>
                                  <div style={{ height: '6px', backgroundColor: theme.gridLine, borderRadius: '4px', overflow: 'hidden' }}>
                                    <div style={{ width: item.value, height: '100%', backgroundColor: item.color }} />
                                  </div>
                                </div>
                              ))}
                              <div style={{ marginTop: '10px', fontSize: '10px', color: theme.textDim }}>Live refresh enabled.</div>
                            </div>
                          </div>
                        </>
                      )
                    }

                    return (
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px', flexWrap: 'wrap' }}>
                          <button onClick={() => recordAction(currentPage.action)} style={{ fontSize: '11px', padding: '6px 10px', borderRadius: '8px', border: `1px solid ${theme.panelBorder}`, backgroundColor: theme.panelBg, color: theme.text, cursor: 'pointer' }}>{currentPage.action}</button>
                          <button onClick={() => recordAction('Refresh data')} style={{ fontSize: '11px', padding: '6px 10px', borderRadius: '8px', border: `1px solid ${theme.panelBorder}`, backgroundColor: 'transparent', color: theme.textDim, cursor: 'pointer' }}>Refresh Data</button>
                          <button onClick={() => recordAction('Open in workspace')} style={{ fontSize: '11px', padding: '6px 10px', borderRadius: '8px', border: `1px solid ${theme.panelBorder}`, backgroundColor: 'transparent', color: theme.textDim, cursor: 'pointer' }}>Open in Workspace</button>
                          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '10px', color: theme.textDim }}>
                            <span>Mode</span>
                            <select value={workspaceMode} onChange={(event) => { setWorkspaceMode(event.target.value as typeof workspaceMode); recordAction(`Mode: ${event.target.value}`) }} style={{ backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, color: theme.text, fontSize: '10px', borderRadius: '6px', padding: '4px 6px' }}>
                              <option value="Standard">Standard</option>
                              <option value="Hardened">Hardened</option>
                              <option value="Forensics">Forensics</option>
                            </select>
                          </div>
                        </div>

                        {activeNav === 'detections' && (
                          <>
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px', marginBottom: '8px' }}>
                              [
                                { label: 'New Alerts', value: '32', color: theme.warning },
                                { label: 'Investigating', value: '11', color: theme.accent },
                                { label: 'SLA Breach', value: '3', color: theme.danger }
                              ].map((item, i) => (
                                <div key={i} style={{ gridColumn: 'span 4', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                  <div>
                                    <div style={{ fontSize: '9px', color: theme.textDim, textTransform: 'uppercase', letterSpacing: '0.8px' }}>{item.label}</div>
                                    <div style={{ fontSize: '16px', fontWeight: '700', color: item.color, marginTop: '4px' }}>{item.value}</div>
                                  </div>
                                  <button onClick={() => recordAction(`${item.label} drill-down`)} style={drillStyle}>Drill</button>
                                </div>
                              ))}
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px' }}>
                              <div style={{ gridColumn: 'span 8', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                                  <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text }}>Detections Queue</div>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '10px', color: theme.textDim, fontFamily: "'Roboto Mono', ui-monospace" }}>
                                    <span>Queue: SOC-21</span>
                                    <button onClick={() => recordAction('Detections queue drill-down')} style={drillStyle}>Drill</button>
                                  </div>
                                </div>
                                <div style={{ border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', overflow: 'hidden' }}>
                                  <div style={{ display: 'grid', gridTemplateColumns: '110px 1fr 120px 90px 90px 70px', padding: '8px 10px', backgroundColor: theme.tableHeaderBg, fontSize: '10px', fontWeight: 600, color: theme.textDim, textTransform: 'uppercase', letterSpacing: '0.8px', fontFamily: "'Roboto Mono', ui-monospace" }}>
                                    <span>Time</span><span>Indicator</span><span>Host</span><span>Owner</span><span>Severity</span><span>Drill</span>
                                  </div>
                                  {filteredDetections.map((row, i) => (
                                    <div key={`${row.time}-${i}`} style={{ display: 'grid', gridTemplateColumns: '110px 1fr 120px 90px 90px 70px', padding: '8px 10px', borderTop: i > 0 ? `1px solid ${theme.panelBorder}` : 'none', fontSize: '11px', color: theme.textMuted }}>
                                      <span style={{ fontFamily: "'Roboto Mono', ui-monospace" }}>{row.time}</span>
                                      <span style={{ fontWeight: 500 }}>{row.ind}</span>
                                      <span style={{ fontFamily: "'Roboto Mono', ui-monospace" }}>SOC-21</span>
                                      <span style={{ fontFamily: "'Roboto Mono', ui-monospace" }}>A. Chen</span>
                                      <span style={{ color: row.color, fontWeight: 600, fontFamily: "'Roboto Mono', ui-monospace" }}>{row.sev}</span>
                                      <button onClick={() => recordAction(`${row.ind} drill-down`)} style={drillStyle}>Drill</button>
                                    </div>
                                  ))}
                                </div>
                              </div>
                              <div style={{ gridColumn: 'span 4', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '8px' }}>Case Detail</div>
                                <div style={{ display: 'grid', gap: '6px', fontSize: '10px', color: theme.textDim }}>
                                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Case ID</span><span style={{ color: theme.text }}>VYR-2041</span></div>
                                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Priority</span><span style={{ color: theme.danger }}>P1</span></div>
                                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Owner</span><span style={{ color: theme.text }}>A. Chen</span></div>
                                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Status</span><span style={{ color: theme.warning }}>Investigating</span></div>
                                  <button onClick={() => recordAction('Case detail drill-down')} style={drillStyle}>Drill</button>
                                </div>
                                <div style={{ marginTop: '10px', fontSize: '10px', color: theme.textDim }}>Evidence: 4 artifacts • 2 hosts.</div>
                              </div>
                            </div>
                          </>
                        )}

                        {activeNav === 'intel' && (
                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px' }}>
                            <div style={{ gridColumn: 'span 7', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text }}>Threat Intel Feeds</div>
                                <button onClick={() => recordAction('Intel feed drill-down')} style={drillStyle}>Drill</button>
                              </div>
                              <div style={{ border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', overflow: 'hidden' }}>
                                <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr 90px 90px 70px', padding: '8px 10px', backgroundColor: theme.tableHeaderBg, fontSize: '10px', fontWeight: 600, color: theme.textDim, textTransform: 'uppercase', letterSpacing: '0.8px', fontFamily: "'Roboto Mono', ui-monospace" }}>
                                  <span>Source</span><span>Indicator</span><span>Confidence</span><span>Last Sync</span><span>Drill</span>
                                </div>
                                {intelFeed.map((row, i) => (
                                  <div key={`${row.source}-${i}`} style={{ display: 'grid', gridTemplateColumns: '120px 1fr 90px 90px 70px', padding: '8px 10px', borderTop: i > 0 ? `1px solid ${theme.panelBorder}` : 'none', fontSize: '11px', color: theme.textMuted }}>
                                    <span style={{ fontFamily: "'Roboto Mono', ui-monospace" }}>{row.source}</span>
                                    <span>{row.indicator}</span>
                                    <span style={{ color: row.confidence === 'High' ? theme.accent : theme.text }}>{row.confidence}</span>
                                    <span style={{ fontFamily: "'Roboto Mono', ui-monospace" }}>{row.lastSync}</span>
                                    <button onClick={() => recordAction(`${row.source} drill-down`)} style={drillStyle}>Drill</button>
                                  </div>
                                ))}
                              </div>
                            </div>
                            <div style={{ gridColumn: 'span 5', display: 'grid', gap: '8px' }}>
                              <div style={{ backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '6px' }}>Campaign Focus</div>
                                {['UNC2970', 'FIN7', 'APT29'].map((campaign) => (
                                  <div key={campaign} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '10px', color: theme.textDim, padding: '6px 0', borderTop: `1px solid ${theme.panelBorder}` }}>
                                    <span>{campaign}</span>
                                    <button onClick={() => recordAction(`${campaign} drill-down`)} style={drillStyle}>Drill</button>
                                  </div>
                                ))}
                              </div>
                              <div style={{ backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '6px' }}>Industry Heat</div>
                                {['Finance 32%', 'Healthcare 21%', 'Manufacturing 18%'].map((row) => (
                                  <div key={row} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: theme.textDim, padding: '4px 0' }}>
                                    <span>{row}</span>
                                    <button onClick={() => recordAction(`${row} drill-down`)} style={drillStyle}>Drill</button>
                                  </div>
                                ))}
                              </div>
                            </div>
                          </div>
                        )}

                        {activeNav === 'hunt' && (
                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px' }}>
                            <div style={{ gridColumn: 'span 8', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text }}>Active Hunts</div>
                                <button onClick={() => recordAction('Hunt sessions drill-down')} style={drillStyle}>Drill</button>
                              </div>
                              <div style={{ border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', overflow: 'hidden' }}>
                                <div style={{ display: 'grid', gridTemplateColumns: '1fr 100px 120px 90px 70px', padding: '8px 10px', backgroundColor: theme.tableHeaderBg, fontSize: '10px', fontWeight: 600, color: theme.textDim, textTransform: 'uppercase', letterSpacing: '0.8px', fontFamily: "'Roboto Mono', ui-monospace" }}>
                                  <span>Query</span><span>Owner</span><span>Scope</span><span>Status</span><span>Drill</span>
                                </div>
                                {huntSessions.map((row, i) => (
                                  <div key={`${row.name}-${i}`} style={{ display: 'grid', gridTemplateColumns: '1fr 100px 120px 90px 70px', padding: '8px 10px', borderTop: i > 0 ? `1px solid ${theme.panelBorder}` : 'none', fontSize: '11px', color: theme.textMuted }}>
                                    <span>{row.name}</span>
                                    <span>{row.owner}</span>
                                    <span>{row.scope}</span>
                                    <span style={{ color: row.status === 'Running' ? theme.accent : theme.textDim }}>{row.status}</span>
                                    <button onClick={() => recordAction(`${row.name} drill-down`)} style={drillStyle}>Drill</button>
                                  </div>
                                ))}
                              </div>
                            </div>
                            <div style={{ gridColumn: 'span 4', display: 'grid', gap: '8px' }}>
                              <div style={{ backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '6px' }}>Query Builder</div>
                                <div style={{ fontSize: '10px', color: theme.textDim, fontFamily: "'Roboto Mono', ui-monospace" }}>
                                  process_name: powershell.exe AND cmdline CONTAINS "-enc"
                                </div>
                                <button onClick={() => recordAction('Query builder drill-down')} style={{ ...drillStyle, marginTop: '6px' }}>Drill</button>
                              </div>
                              <div style={{ backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '6px' }}>Telemetry Scope</div>
                                {['Endpoints: 684', 'Servers: 214', 'Network: 86'].map((row) => (
                                  <div key={row} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: theme.textDim, padding: '4px 0' }}>
                                    <span>{row}</span>
                                    <button onClick={() => recordAction(`${row} drill-down`)} style={drillStyle}>Drill</button>
                                  </div>
                                ))}
                              </div>
                            </div>
                          </div>
                        )}

                        {activeNav === 'risk' && (
                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px' }}>
                            <div style={{ gridColumn: 'span 7', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text }}>Top Exposed Assets</div>
                                <button onClick={() => recordAction('Risk assets drill-down')} style={drillStyle}>Drill</button>
                              </div>
                              <div style={{ border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', overflow: 'hidden' }}>
                                <div style={{ display: 'grid', gridTemplateColumns: '1fr 110px 80px 90px 70px', padding: '8px 10px', backgroundColor: theme.tableHeaderBg, fontSize: '10px', fontWeight: 600, color: theme.textDim, textTransform: 'uppercase', letterSpacing: '0.8px', fontFamily: "'Roboto Mono', ui-monospace" }}>
                                  <span>Asset</span><span>Owner</span><span>CVSS</span><span>Exposure</span><span>Drill</span>
                                </div>
                                {riskAssets.map((row, i) => (
                                  <div key={`${row.asset}-${i}`} style={{ display: 'grid', gridTemplateColumns: '1fr 110px 80px 90px 70px', padding: '8px 10px', borderTop: i > 0 ? `1px solid ${theme.panelBorder}` : 'none', fontSize: '11px', color: theme.textMuted }}>
                                    <span>{row.asset}</span>
                                    <span>{row.owner}</span>
                                    <span style={{ color: theme.danger }}>{row.cvss}</span>
                                    <span>{row.exposure}</span>
                                    <button onClick={() => recordAction(`${row.asset} drill-down`)} style={drillStyle}>Drill</button>
                                  </div>
                                ))}
                              </div>
                            </div>
                            <div style={{ gridColumn: 'span 5', display: 'grid', gap: '8px' }}>
                              <div style={{ backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '6px' }}>Coverage Gaps</div>
                                {['Legacy OS coverage', 'Email sandbox', 'Cloud audit'].map((row) => (
                                  <div key={row} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: theme.textDim, padding: '6px 0', borderTop: `1px solid ${theme.panelBorder}` }}>
                                    <span>{row}</span>
                                    <button onClick={() => recordAction(`${row} drill-down`)} style={drillStyle}>Drill</button>
                                  </div>
                                ))}
                              </div>
                              <div style={{ backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '6px' }}>Control Health</div>
                                {['EDR: 96%', 'NDR: 88%', 'Email: 82%'].map((row) => (
                                  <div key={row} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: theme.textDim, padding: '4px 0' }}>
                                    <span>{row}</span>
                                    <button onClick={() => recordAction(`${row} drill-down`)} style={drillStyle}>Drill</button>
                                  </div>
                                ))}
                              </div>
                            </div>
                          </div>
                        )}

                        {activeNav === 'timeline' && (
                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '8px' }}>
                            <div style={{ gridColumn: 'span 8', backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text }}>Incident Timeline</div>
                                <button onClick={() => recordAction('Timeline drill-down')} style={drillStyle}>Drill</button>
                              </div>
                              <div style={{ display: 'grid', gap: '6px' }}>
                                {timelineEvents.map((row, i) => (
                                  <div key={`${row.time}-${i}`} style={{ display: 'grid', gridTemplateColumns: '90px 1fr 110px 90px 70px', alignItems: 'center', gap: '8px', padding: '6px 8px', border: `1px solid ${theme.panelBorder}`, borderRadius: '6px' }}>
                                    <span style={{ fontFamily: "'Roboto Mono', ui-monospace", color: theme.textDim }}>{row.time}</span>
                                    <span style={{ fontSize: '11px', color: theme.text }}>{row.event}</span>
                                    <span style={{ fontSize: '10px', color: theme.textDim }}>{row.actor}</span>
                                    <span style={{ fontSize: '10px', color: theme.textDim }}>{row.status}</span>
                                    <button onClick={() => recordAction(`${row.event} drill-down`)} style={drillStyle}>Drill</button>
                                  </div>
                                ))}
                              </div>
                            </div>
                            <div style={{ gridColumn: 'span 4', display: 'grid', gap: '8px' }}>
                              <div style={{ backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '6px' }}>Case Actions</div>
                                {['Contain host', 'Preserve memory', 'Notify legal'].map((row) => (
                                  <div key={row} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: theme.textDim, padding: '6px 0', borderTop: `1px solid ${theme.panelBorder}` }}>
                                    <span>{row}</span>
                                    <button onClick={() => recordAction(`${row} drill-down`)} style={drillStyle}>Drill</button>
                                  </div>
                                ))}
                              </div>
                              <div style={{ backgroundColor: theme.panelBg, border: `1px solid ${theme.panelBorder}`, borderRadius: '6px', padding: '8px' }}>
                                <div style={{ fontSize: '11px', fontWeight: '700', color: theme.text, marginBottom: '6px' }}>Artifacts</div>
                                {['3 memory dumps', '12 IOC hashes', '2 packet captures'].map((row) => (
                                  <div key={row} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: theme.textDim, padding: '4px 0' }}>
                                    <span>{row}</span>
                                    <button onClick={() => recordAction(`${row} drill-down`)} style={drillStyle}>Drill</button>
                                  </div>
                                ))}
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    )
                  }

                  return (
                    <div style={{ minHeight: '100vh', backgroundColor: theme.bg, color: theme.text, fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif", display: 'flex' }}>
                      <aside style={{ width: '248px', backgroundColor: theme.sidebarBg, borderRight: `1px solid ${theme.cardBorder}`, display: 'flex', flexDirection: 'column', position: 'fixed', left: 0, top: 0, bottom: 0, zIndex: 100, padding: '18px 14px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '6px 6px 18px' }}>
                          <div style={{ width: '34px', height: '34px', borderRadius: '10px', background: `linear-gradient(135deg, ${theme.accent}, #0E8D8A)`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '14px', fontWeight: '700', color: '#fff', flexShrink: 0 }}>V</div>
                          <div style={{ overflow: 'hidden' }}>
                            <div style={{ fontSize: '15px', fontWeight: '700', color: theme.text, letterSpacing: '-0.3px' }}>Vyron</div>
                            <div style={{ fontSize: '10px', color: theme.textMuted, textTransform: 'uppercase', letterSpacing: '0.6px' }}>Security</div>
                          </div>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', backgroundColor: theme.surface, border: `1px solid ${theme.cardBorder}`, borderRadius: '12px', padding: '6px 10px', height: '36px', marginBottom: '14px' }}>
                          <Search size={14} color={theme.textDim} />
                          <input type="text" placeholder="Search Vyron" value={sidebarQuery} onChange={(event) => setSidebarQuery(event.target.value)} style={{ border: 'none', background: 'transparent', outline: 'none', fontSize: '12px', color: theme.text, width: '100%', fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif" }} />
                          <kbd style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', height: '18px', minWidth: '34px', padding: '0 8px', fontSize: '10px', fontWeight: 600, lineHeight: '18px', letterSpacing: '0.3px', fontFamily: "'Roboto Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace", whiteSpace: 'nowrap', textAlign: 'center', backgroundColor: theme.kbdBg, borderRadius: '6px', color: theme.textDim, border: `1px solid ${theme.cardBorder}` }}>⌘ K</kbd>
                        </div>

                        <div style={{ padding: '2px 6px 8px', fontSize: '9px', fontWeight: 600, color: theme.textDim, textTransform: 'uppercase', letterSpacing: '1.6px', fontFamily: "'Roboto Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace" }}>Navigation</div>

                        <nav style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          {visibleNavItems.length === 0 && (
                            <div style={{ padding: '8px 10px', fontSize: '11px', color: theme.textDim }}>No matches</div>
                          )}
                          {visibleNavItems.map((item) => (
                            <button key={item.id} onClick={() => { setActiveNav(item.id); recordAction(`Open ${item.label}`) }} style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 10px', borderRadius: '9px', backgroundColor: activeNav === item.id ? theme.surfaceAlt : 'transparent', border: activeNav === item.id ? `1px solid ${theme.cardBorder}` : '1px solid transparent', color: activeNav === item.id ? theme.text : theme.textMuted, cursor: 'pointer', transition: 'all 0.2s ease', width: '100%', justifyContent: 'flex-start' }}>
                              <item.icon size={15} strokeWidth={1.6} />
                              <span style={{ fontSize: '12px', fontWeight: 500, letterSpacing: '0.2px', whiteSpace: 'nowrap' }}>{item.label}</span>
                            </button>
                          ))}
                        </nav>
                      </aside>

                      <main style={{ flex: 1, marginLeft: '248px' }}>
                        <header style={{ height: '64px', backgroundColor: theme.headerBg, borderBottom: `1px solid ${theme.panelBorder}`, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px', position: 'sticky', top: 0, zIndex: 50 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                            <div style={{ fontSize: '12px', letterSpacing: '1.2px', color: theme.textDim, textTransform: 'uppercase' }}>Vyron SOC</div>
                            <div style={{ width: '1px', height: '18px', backgroundColor: theme.panelBorder }} />
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', backgroundColor: theme.surface, border: `1px solid ${theme.panelBorder}`, borderRadius: '12px', padding: '8px 12px', width: '380px' }}>
                              <Search size={16} color={theme.textDim} />
                              <input type="text" placeholder="Search threats, files, endpoints..." value={globalQuery} onChange={(event) => setGlobalQuery(event.target.value)} style={{ border: 'none', background: 'transparent', outline: 'none', fontSize: '13px', color: theme.text, width: '100%', fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif" }} />
                              <kbd style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', height: '20px', minWidth: '52px', padding: '0 8px', fontSize: '10px', fontWeight: 600, lineHeight: '20px', letterSpacing: '0.3px', fontFamily: "'Roboto Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace", whiteSpace: 'nowrap', textAlign: 'center', backgroundColor: theme.kbdBg, borderRadius: '6px', color: theme.textDim, border: `1px solid ${theme.panelBorder}` }}>Ctrl+K</kbd>
                            </div>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                            <button onClick={() => setDarkMode(!darkMode)} style={{ width: '36px', height: '36px', borderRadius: '10px', backgroundColor: theme.buttonBg, border: `1px solid ${theme.panelBorder}`, color: theme.textMuted, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{darkMode ? <Sun size={16} /> : <Moon size={16} />}</button>
                            <button style={{ width: '36px', height: '36px', borderRadius: '10px', backgroundColor: theme.buttonBg, border: `1px solid ${theme.panelBorder}`, color: theme.textMuted, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative' }}><Bell size={16} /><div style={{ position: 'absolute', top: '7px', right: '7px', width: '7px', height: '7px', backgroundColor: theme.danger, borderRadius: '50%', border: `2px solid ${theme.notificationBorder}` }} /></button>
                            <div style={{ width: '1px', height: '22px', backgroundColor: theme.panelBorder, margin: '0 6px' }} />
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                              <div style={{ width: '34px', height: '34px', borderRadius: '10px', background: 'linear-gradient(135deg, #6366F1, #8B5CF6)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', fontWeight: '600', color: '#fff' }}>AD</div>
                              <div><div style={{ fontSize: '13px', fontWeight: '600', color: theme.text }}>Admin User</div><div style={{ fontSize: '11px', color: theme.textDim }}>admin@vyron.io</div></div>
                              <ChevronDown size={14} color={theme.textMuted} />
                            </div>
                          </div>
                        </header>

                        <div style={{ padding: '16px 22px 24px', backgroundColor: theme.bg }}>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                            <div>
                              <div style={{ fontSize: '11px', color: theme.textDim, letterSpacing: '1.4px', textTransform: 'uppercase' }}>{currentPage.subtitle}</div>
                              <div style={{ fontSize: '18px', fontWeight: '700', color: theme.text }}>{currentPage.title}</div>
                              {lastAction && <div style={{ marginTop: '4px', fontSize: '10px', color: theme.textDim }}>{lastAction}</div>}
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '11px', color: theme.textDim, fontFamily: "'Roboto Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace" }}>
                              <span>Live</span>
                              <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: theme.accent }} />
                              <span>Refresh 15s</span>
                              <span style={{ border: `1px solid ${theme.panelBorder}`, padding: '4px 6px', borderRadius: '6px', backgroundColor: theme.panelBg }}>UTC</span>
                            </div>
                          </div>

                          {renderPagePanels()}
                        </div>
                      </main>
                    </div>
                  )
                }

                export default App
*/