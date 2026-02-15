'use client'

import { useState, useEffect, FormEvent } from 'react'
import { useRouter } from 'next/navigation'

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

export default function UploadPage() {
  const router = useRouter()
  const [file, setFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState('')
  const [email, setEmail] = useState('')

  useEffect(() => {
    const token = localStorage.getItem('token')
    const userEmail = localStorage.getItem('email')
    if (!token) {
      router.push('/login')
      return
    }
    setEmail(userEmail || '')
  }, [router])

  const handleLogout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('email')
    router.push('/login')
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (!file) return

    setError('')
    setUploading(true)

    try {
      const token = localStorage.getItem('token')
      const formData = new FormData()
      formData.append('file', file)

      const response = await fetch(`${API_URL}/api/analyze`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        },
        body: formData
      })

      if (!response.ok) {
        if (response.status === 401) {
          localStorage.removeItem('token')
          router.push('/login')
          return
        }
        throw new Error('Analysis failed')
      }

      const data = await response.json()
      localStorage.setItem('lastAnalysis', JSON.stringify(data))
      router.push('/results')
    } catch (err: any) {
      setError(err.message || 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

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

      <main style={{ maxWidth: '800px', margin: '3rem auto', padding: '0 2rem' }}>
        <div style={{
          backgroundColor: 'white',
          padding: '2rem',
          borderRadius: '8px',
          boxShadow: '0 2px 10px rgba(0,0,0,0.1)'
        }}>
          <h2 style={{ marginTop: 0 }}>Upload Log File</h2>
          <p style={{ color: '#666' }}>
            Upload a JSONL log file for analysis. Supports Zscaler-style web proxy logs.
          </p>

          <form onSubmit={handleSubmit} style={{ marginTop: '1.5rem' }}>
            <div style={{ marginBottom: '1rem' }}>
              <input
                type="file"
                accept=".jsonl,.log"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
                style={{
                  display: 'block',
                  width: '100%',
                  padding: '0.75rem',
                  border: '2px dashed #ddd',
                  borderRadius: '4px',
                  cursor: 'pointer'
                }}
              />
              {file && (
                <div style={{
                  marginTop: '0.5rem',
                  fontSize: '0.875rem',
                  color: '#666'
                }}>
                  Selected: {file.name} ({(file.size / 1024).toFixed(1)} KB)
                </div>
              )}
            </div>

            {error && (
              <div style={{
                padding: '0.75rem',
                backgroundColor: '#fee',
                color: '#c33',
                borderRadius: '4px',
                marginBottom: '1rem',
                fontSize: '0.875rem'
              }}>
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={!file || uploading}
              style={{
                width: '100%',
                padding: '0.75rem',
                backgroundColor: '#0066cc',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                fontSize: '1rem',
                cursor: (!file || uploading) ? 'not-allowed' : 'pointer',
                opacity: (!file || uploading) ? 0.6 : 1
              }}
            >
              {uploading ? 'Analyzing...' : 'Analyze Log File'}
            </button>
          </form>
        </div>

        <div style={{
          marginTop: '2rem',
          padding: '1.5rem',
          backgroundColor: 'white',
          borderRadius: '8px',
          boxShadow: '0 2px 10px rgba(0,0,0,0.1)'
        }}>
          <h3 style={{ marginTop: 0, fontSize: '1rem' }}>Sample Log Files</h3>
          <p style={{ fontSize: '0.875rem', color: '#666' }}>
            Example files are available in the <code style={{
              padding: '0.125rem 0.25rem',
              backgroundColor: '#f5f5f5',
              borderRadius: '3px',
              fontSize: '0.8em'
            }}>data/</code> directory:
          </p>
          <ul style={{ fontSize: '0.875rem', lineHeight: 1.6 }}>
            <li><strong>baseline_small.jsonl</strong> - Normal traffic (1,000 events)</li>
            <li><strong>anomalous_credential_stuffing.jsonl</strong> - High burst + deny rate</li>
            <li><strong>anomalous_exfiltration.jsonl</strong> - Large data transfer</li>
            <li><strong>anomalous_scanning.jsonl</strong> - Multiple hosts scan</li>
          </ul>
        </div>
      </main>
    </div>
  )
}
