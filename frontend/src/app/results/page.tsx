'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'

interface Anomaly {
  clientip: string
  severity: string
  confidence: number
  detection_method: string
  triggered_rules: string[]
  features: any
  isolation_score: number
  explanation: string
  first_seen: string
  request_count: number
}

interface AnalysisData {
  filename: string
  total_logs: number
  anomaly_count: number
  risk_level: string
  summary: string
  detection_breakdown: { rule_based: number; statistical: number; hybrid: number; total: number; note?: string }
  time_range: { start: string; end: string; duration_hours: number }
  peak_activity?: { hour: number; event_count: number }
  timeline: Array<{ timestamp: string; clientip: string; detection_type: string; severity: string }>
  anomalies: Anomaly[]
  logs: Array<{ time: string; clientip: string; host: string; action: string; responsecode: number; is_anomalous: boolean }>
}

export default function ResultsPage() {
  const router = useRouter()
  const [data, setData] = useState<AnalysisData | null>(null)
  const [showAllLogs, setShowAllLogs] = useState(false)
  const [email, setEmail] = useState('')

  useEffect(() => {
    const token = localStorage.getItem('token')
    const userEmail = localStorage.getItem('email')
    const lastAnalysis = localStorage.getItem('lastAnalysis')

    if (!token) {
      router.push('/login')
      return
    }

    if (!lastAnalysis) {
      router.push('/upload')
      return
    }

    setEmail(userEmail || '')
    setData(JSON.parse(lastAnalysis))
  }, [router])

  const handleLogout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('email')
    localStorage.removeItem('lastAnalysis')
    router.push('/login')
  }

  const handleNewAnalysis = () => {
    router.push('/upload')
  }

  if (!data) {
    return <div>Loading...</div>
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return '#dc2626'
      case 'High': return '#ea580c'
      case 'Medium': return '#ca8a04'
      case 'Low': return '#0284c7'
      default: return '#666'
    }
  }

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'High': return '#dc2626'
      case 'Medium': return '#ea580c'
      case 'Low': return '#0284c7'
      default: return '#666'
    }
  }

  // Always show all logs if there are no anomalies, otherwise allow filtering
  const displayedLogs = showAllLogs || data.anomaly_count === 0 
    ? data.logs 
    : data.logs.filter(log => log.is_anomalous)

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#f5f5f5' }}>
      <header style={{
        backgroundColor: 'white',
        borderBottom: '1px solid #e0e0e0',
        padding: '1rem 2rem'
      }}>
        <div style={{
          maxWidth: '1200px',
          margin: '0 auto',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <h1 style={{ margin: 0, fontSize: '1.25rem' }}>signaltrace</h1>
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
            <button
              onClick={handleNewAnalysis}
              style={{
                padding: '0.5rem 1rem',
                backgroundColor: '#0066cc',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '0.875rem'
              }}
            >
              New Analysis
            </button>
            <span style={{ fontSize: '0.875rem', color: '#666' }}>{email}</span>
            <button
              onClick={handleLogout}
              style={{
                padding: '0.5rem 1rem',
                backgroundColor: '#f5f5f5',
                border: '1px solid #ddd',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '0.875rem'
              }}
            >
              Logout
            </button>
          </div>
        </div>
      </header>

      <main style={{ maxWidth: '1200px', margin: '2rem auto', padding: '0 2rem' }}>
        {/* 1. Summary Card */}
        <div style={{
          backgroundColor: 'white',
          padding: '2rem',
          borderRadius: '8px',
          boxShadow: '0 2px 10px rgba(0,0,0,0.1)',
          marginBottom: '1.5rem'
        }}>
          <h2 style={{ marginTop: 0, fontSize: '1.5rem' }}>Analysis Summary</h2>
          
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
            <div>
              <div style={{ fontSize: '0.875rem', color: '#666' }}>File</div>
              <div style={{ fontWeight: 500 }}>{data.filename}</div>
            </div>
            <div>
              <div style={{ fontSize: '0.875rem', color: '#666' }}>Total Logs</div>
              <div style={{ fontWeight: 500 }}>{data.total_logs}</div>
            </div>
            <div>
              <div style={{ fontSize: '0.875rem', color: '#666' }}>Time Range</div>
              <div style={{ fontWeight: 500 }}>{data.time_range.duration_hours}h</div>
            </div>
            {data.peak_activity && (
              <div>
                <div style={{ fontSize: '0.875rem', color: '#666' }}>Peak Activity</div>
                <div style={{ fontWeight: 500 }}>Hour {data.peak_activity.hour} ({data.peak_activity.event_count} events)</div>
              </div>
            )}
          </div>

          <div style={{ marginBottom: '1.5rem' }}>
            <div style={{ fontSize: '0.875rem', color: '#666', marginBottom: '0.5rem' }}>Anomalies Detected</div>
            <div style={{ fontSize: '2rem', fontWeight: 'bold' }}>{data.anomaly_count}</div>
            <div style={{ fontSize: '1rem', fontWeight: 500, color: getRiskColor(data.risk_level) }}>
              Risk Level: {data.risk_level}
            </div>
          </div>

          <div style={{ marginBottom: '1.5rem' }}>
            <div style={{ fontSize: '0.875rem', fontWeight: 500, marginBottom: '0.5rem' }}>Detection Breakdown</div>
            <div style={{ fontSize: '0.875rem', color: '#666' }}>
                    Rule-based: {data.detection_breakdown.rule_based} | 
                    Statistical: {data.detection_breakdown.statistical} | 
                    Hybrid: {data.detection_breakdown.hybrid || 0} | 
                    Total: {data.detection_breakdown.total}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: '#999', marginTop: '0.25rem' }}>
                    Hybrid = Both rule triggers AND statistical anomaly
                  </div>
                </div>

          <div style={{
            padding: '1rem',
            backgroundColor: '#f0f8ff',
            borderRadius: '4px',
            borderLeft: '4px solid #0066cc'
          }}>
            <div style={{ fontSize: '0.875rem', fontWeight: 500, marginBottom: '0.5rem' }}>Summary</div>
            <div style={{ fontSize: '0.875rem', lineHeight: 1.6 }}>{data.summary}</div>
          </div>
        </div>

        {/* 2. Timeline */}
        {data.timeline.length > 0 && (
          <div style={{
            backgroundColor: 'white',
            padding: '2rem',
            borderRadius: '8px',
            boxShadow: '0 2px 10px rgba(0,0,0,0.1)',
            marginBottom: '1.5rem'
          }}>
            <h2 style={{ marginTop: 0, fontSize: '1.5rem' }}>Timeline of Events</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {data.timeline.map((event, idx) => (
                <div key={idx} style={{ 
                  borderLeft: `3px solid ${getSeverityColor(event.severity)}`,
                  paddingLeft: '1rem'
                }}>
                  <div style={{ fontSize: '0.875rem', color: '#666' }}>
                    {new Date(event.timestamp).toLocaleString()}
                  </div>
                  <div style={{ fontWeight: 500 }}>{event.detection_type}</div>
                  <div style={{ fontSize: '0.875rem' }}>
                    IP: {event.clientip} | 
                    <span style={{ color: getSeverityColor(event.severity), marginLeft: '0.5rem' }}>
                      {event.severity}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* 3. Anomaly Cards */}
        {data.anomalies.length > 0 && (
          <div style={{ marginBottom: '1.5rem' }}>
            <h2 style={{ fontSize: '1.5rem', marginBottom: '1rem' }}>Anomalies</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {data.anomalies.map((anomaly, idx) => (
                <div key={idx} style={{
                  backgroundColor: 'white',
                  padding: '1.5rem',
                  borderRadius: '8px',
                  boxShadow: '0 2px 10px rgba(0,0,0,0.1)',
                  borderLeft: `4px solid ${getSeverityColor(anomaly.severity)}`
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '1rem' }}>
                    <div>
                      <div style={{ fontSize: '1.125rem', fontWeight: 600, marginBottom: '0.25rem' }}>
                        {anomaly.clientip}
                      </div>
                      <div style={{ fontSize: '0.875rem', color: '#666' }}>
                        {anomaly.request_count} requests | First seen: {new Date(anomaly.first_seen).toLocaleString()}
                      </div>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      <div style={{ fontSize: '0.875rem', color: getSeverityColor(anomaly.severity), fontWeight: 600 }}>
                        {anomaly.severity}
                      </div>
                      <div style={{ fontSize: '0.875rem', color: '#666' }}>
                        Confidence: {(anomaly.confidence * 100).toFixed(0)}%
                      </div>
                      <div style={{ fontSize: '0.75rem', color: '#999', marginTop: '0.25rem' }}>
                        {anomaly.detection_method}
                      </div>
                    </div>
                  </div>

                  {anomaly.triggered_rules.length > 0 && (
                    <div style={{ marginBottom: '1rem' }}>
                      <div style={{ fontSize: '0.875rem', fontWeight: 500, marginBottom: '0.5rem' }}>
                        Triggered Rules:
                      </div>
                      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                        {anomaly.triggered_rules.map((rule, rIdx) => (
                          <span key={rIdx} style={{
                            padding: '0.25rem 0.75rem',
                            backgroundColor: '#fee',
                            color: '#c33',
                            borderRadius: '12px',
                            fontSize: '0.75rem',
                            fontWeight: 500,
                            marginRight: '0.5rem'
                          }}>
                            {rule}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <div style={{ marginBottom: '1rem' }}>
                    <div style={{ fontSize: '0.875rem', fontWeight: 500, marginBottom: '0.5rem' }}>
                      Feature Values:
                    </div>
                    <div style={{ 
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                      gap: '0.5rem',
                      fontSize: '0.75rem'
                    }}>
                      <div>Peak Rate: {anomaly.features.requests_per_minute_peak} req/min</div>
                      <div>Deny Rate: {(anomaly.features.deny_rate * 100).toFixed(0)}%</div>
                      <div>Total Bytes: {(anomaly.features.total_bytes_transferred / 1024 / 1024).toFixed(2)} MB</div>
                      <div>Unique Hosts: {anomaly.features.unique_hosts_count}</div>
                      <div>Off-Hours: {(anomaly.features.off_hours_request_ratio * 100).toFixed(0)}%</div>
                      {anomaly.isolation_score > 0 && (
                        <div>IF Score: {anomaly.isolation_score.toFixed(2)}</div>
                      )}
                    </div>
                  </div>

                  <div style={{
                    padding: '0.75rem',
                    backgroundColor: '#f9fafb',
                    borderRadius: '4px',
                    fontSize: '0.875rem',
                    lineHeight: 1.5
                  }}>
                    {anomaly.explanation}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* 4. Raw Logs Table */}
        <div style={{
          backgroundColor: 'white',
          padding: '2rem',
          borderRadius: '8px',
          boxShadow: '0 2px 10px rgba(0,0,0,0.1)'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h2 style={{ margin: 0, fontSize: '1.5rem' }}>
              All Logs ({displayedLogs.length})
            </h2>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                onClick={() => setShowAllLogs(true)}
                style={{
                  padding: '0.5rem 1rem',
                  backgroundColor: showAllLogs ? '#0066cc' : 'white',
                  color: showAllLogs ? 'white' : '#666',
                  border: '1px solid #ddd',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  fontSize: '0.875rem'
                }}
              >
                All
              </button>
              <button
                onClick={() => setShowAllLogs(false)}
                style={{
                  padding: '0.5rem 1rem',
                  backgroundColor: !showAllLogs ? '#0066cc' : 'white',
                  color: !showAllLogs ? 'white' : '#666',
                  border: '1px solid #ddd',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  fontSize: '0.875rem'
                }}
              >
                Anomalies Only
              </button>
            </div>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
              <thead>
                <tr style={{ backgroundColor: '#f9fafb', borderBottom: '2px solid #e5e7eb' }}>
                  <th style={{ padding: '0.75rem', textAlign: 'left' }}>Time</th>
                  <th style={{ padding: '0.75rem', textAlign: 'left' }}>Client IP</th>
                  <th style={{ padding: '0.75rem', textAlign: 'left' }}>Host</th>
                  <th style={{ padding: '0.75rem', textAlign: 'left' }}>Action</th>
                  <th style={{ padding: '0.75rem', textAlign: 'left' }}>Code</th>
                  <th style={{ padding: '0.75rem', textAlign: 'center' }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {displayedLogs.slice(0, 100).map((log, idx) => (
                  <tr key={idx} style={{
                    backgroundColor: log.is_anomalous ? '#fff1f1' : 'white',
                    borderBottom: '1px solid #e5e7eb'
                  }}>
                    <td style={{ padding: '0.75rem' }}>
                      {new Date(log.time).toLocaleTimeString()}
                    </td>
                    <td style={{ padding: '0.75rem', fontFamily: 'monospace', fontSize: '0.8em' }}>
                      {log.clientip}
                    </td>
                    <td style={{ padding: '0.75rem', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {log.host}
                    </td>
                    <td style={{ padding: '0.75rem' }}>
                      <span style={{
                        padding: '0.25rem 0.5rem',
                        backgroundColor: log.action === 'ALLOW' ? '#dcfce7' : '#fee2e2',
                        color: log.action === 'ALLOW' ? '#166534' : '#991b1b',
                        borderRadius: '4px',
                        fontSize: '0.75rem',
                        fontWeight: 500
                      }}>
                        {log.action}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem' }}>{log.responsecode}</td>
                    <td style={{ padding: '0.75rem', textAlign: 'center' }}>
                      {log.is_anomalous && <span style={{ color: '#dc2626' }}>⚠️</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {displayedLogs.length > 100 && (
              <div style={{ padding: '1rem', textAlign: 'center', color: '#666', fontSize: '0.875rem' }}>
                Showing first 100 of {displayedLogs.length} logs
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  )
}
