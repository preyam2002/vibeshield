import { describe, it, expect, beforeEach } from 'vitest'
import {
  createScan,
  getScan,
  getActiveScansCount,
  findActiveScan,
  updateScanStatus,
  addFindings,
  setModules,
  updateModule,
  setTechInfo,
  cancelScan,
  getStats,
  getRecentScans,
  getScanHistory,
  registerAbort,
} from '../store'
import type { Finding, ModuleStatus } from '../types'

// Clear global state before each test by clearing the existing maps
beforeEach(() => {
  const g = globalThis as any
  if (g.__vibeshieldScans) g.__vibeshieldScans.clear()
  else g.__vibeshieldScans = new Map()
  if (g.__vibeshieldAbort) g.__vibeshieldAbort.clear()
  else g.__vibeshieldAbort = new Map()
})

describe('createScan', () => {
  it('creates a scan with correct initial state', () => {
    const scan = createScan('test-1', 'https://example.com', 'security')
    expect(scan.id).toBe('test-1')
    expect(scan.target).toBe('https://example.com')
    expect(scan.status).toBe('queued')
    expect(scan.mode).toBe('security')
    expect(scan.score).toBe(100)
    expect(scan.grade).toBe('-')
    expect(scan.findings).toHaveLength(0)
    expect(scan.summary.total).toBe(0)
  })

  it('defaults mode to full', () => {
    const scan = createScan('test-2', 'https://example.com')
    expect(scan.mode).toBe('full')
  })
})

describe('getScan', () => {
  it('returns created scan', () => {
    createScan('abc', 'https://a.com')
    expect(getScan('abc')).toBeDefined()
    expect(getScan('abc')!.target).toBe('https://a.com')
  })

  it('returns undefined for non-existent scan', () => {
    expect(getScan('nonexistent')).toBeUndefined()
  })
})

describe('getActiveScansCount', () => {
  it('counts queued and scanning scans', () => {
    createScan('s1', 'https://a.com')
    createScan('s2', 'https://b.com')
    updateScanStatus('s1', 'scanning')
    expect(getActiveScansCount()).toBe(2) // s1=scanning, s2=queued
    updateScanStatus('s2', 'completed')
    expect(getActiveScansCount()).toBe(1) // only s1
  })
})

describe('findActiveScan', () => {
  it('finds an active scan for a target', () => {
    createScan('s1', 'https://example.com')
    updateScanStatus('s1', 'scanning')
    expect(findActiveScan('https://example.com')).toBeDefined()
  })

  it('returns undefined for completed targets', () => {
    createScan('s1', 'https://example.com')
    updateScanStatus('s1', 'completed')
    expect(findActiveScan('https://example.com')).toBeUndefined()
  })
})

describe('updateScanStatus', () => {
  it('updates status correctly', () => {
    createScan('s1', 'https://example.com')
    updateScanStatus('s1', 'scanning')
    expect(getScan('s1')!.status).toBe('scanning')
  })

  it('sets completedAt when completing', () => {
    createScan('s1', 'https://example.com')
    updateScanStatus('s1', 'completed')
    expect(getScan('s1')!.completedAt).toBeDefined()
  })

  it('sets error message on failure', () => {
    createScan('s1', 'https://example.com')
    updateScanStatus('s1', 'failed', 'timeout')
    expect(getScan('s1')!.error).toBe('timeout')
  })
})

describe('addFindings', () => {
  const makeFinding = (id: string, severity: Finding['severity'] = 'medium', module = 'test'): Finding => ({
    id,
    module,
    severity,
    title: `Finding ${id}`,
    description: 'test',
    remediation: 'fix it',
  })

  it('adds findings and recalculates summary', () => {
    createScan('s1', 'https://example.com')
    addFindings('s1', [makeFinding('f1', 'high'), makeFinding('f2', 'low')])
    const scan = getScan('s1')!
    expect(scan.findings).toHaveLength(2)
    expect(scan.summary.high).toBe(1)
    expect(scan.summary.low).toBe(1)
    expect(scan.summary.total).toBe(2)
  })

  it('deduplicates findings by module+title', () => {
    createScan('s1', 'https://example.com')
    addFindings('s1', [makeFinding('f1', 'high', 'headers')])
    addFindings('s1', [makeFinding('f1', 'high', 'headers')]) // same module+title
    expect(getScan('s1')!.findings).toHaveLength(1)
  })

  it('allows same title from different modules', () => {
    createScan('s1', 'https://example.com')
    addFindings('s1', [makeFinding('f1', 'high', 'headers')])
    addFindings('s1', [makeFinding('f1', 'high', 'ssl')]) // different module
    expect(getScan('s1')!.findings).toHaveLength(2)
  })

  it('updates grade based on findings', () => {
    createScan('s1', 'https://example.com')
    addFindings('s1', [
      makeFinding('c1', 'critical'),
      makeFinding('c2', 'critical'),
      makeFinding('h1', 'high'),
      makeFinding('h2', 'high'),
      makeFinding('h3', 'high'),
    ])
    const scan = getScan('s1')!
    expect(scan.score).toBeLessThan(50)
    expect(['D', 'D+', 'F']).toContain(scan.grade)
  })

  it('score stays 100 with only info findings', () => {
    createScan('s1', 'https://example.com')
    addFindings('s1', [makeFinding('i1', 'info'), makeFinding('i2', 'info')])
    expect(getScan('s1')!.score).toBe(100)
  })
})

describe('setModules and updateModule', () => {
  it('sets and updates module status', () => {
    createScan('s1', 'https://example.com')
    const modules: ModuleStatus[] = [
      { name: 'headers', status: 'pending', findingsCount: 0 },
      { name: 'ssl', status: 'pending', findingsCount: 0 },
    ]
    setModules('s1', modules)
    expect(getScan('s1')!.modules).toHaveLength(2)

    updateModule('s1', 'headers', { status: 'completed', findingsCount: 3 })
    const headersMod = getScan('s1')!.modules.find(m => m.name === 'headers')
    expect(headersMod!.status).toBe('completed')
    expect(headersMod!.findingsCount).toBe(3)
  })
})

describe('setTechInfo', () => {
  it('sets technologies and SPA flag', () => {
    createScan('s1', 'https://example.com')
    setTechInfo('s1', ['Next.js', 'React'], true)
    const scan = getScan('s1')!
    expect(scan.technologies).toEqual(['Next.js', 'React'])
    expect(scan.isSpa).toBe(true)
  })
})

describe('cancelScan', () => {
  it('cancels a scanning scan', () => {
    createScan('s1', 'https://example.com')
    updateScanStatus('s1', 'scanning')
    const controller = new AbortController()
    registerAbort('s1', controller)
    expect(cancelScan('s1')).toBe(true)
    expect(getScan('s1')!.status).toBe('failed')
    expect(getScan('s1')!.error).toContain('cancelled')
  })

  it('returns false for completed scan', () => {
    createScan('s1', 'https://example.com')
    updateScanStatus('s1', 'completed')
    expect(cancelScan('s1')).toBe(false)
  })

  it('marks pending modules as skipped', () => {
    createScan('s1', 'https://example.com')
    updateScanStatus('s1', 'scanning')
    setModules('s1', [
      { name: 'a', status: 'completed', findingsCount: 0 },
      { name: 'b', status: 'pending', findingsCount: 0 },
      { name: 'c', status: 'running', findingsCount: 0 },
    ])
    cancelScan('s1')
    const mods = getScan('s1')!.modules
    expect(mods.find(m => m.name === 'a')!.status).toBe('completed')
    expect(mods.find(m => m.name === 'b')!.status).toBe('skipped')
    expect(mods.find(m => m.name === 'c')!.status).toBe('skipped')
  })
})

describe('getStats', () => {
  it('returns stats for completed scans', () => {
    createScan('s1', 'https://a.com')
    addFindings('s1', [
      { id: 'f1', module: 'headers', severity: 'high', title: 'Missing CSP', description: '', remediation: '' },
    ])
    updateScanStatus('s1', 'completed')

    createScan('s2', 'https://b.com')
    updateScanStatus('s2', 'completed')

    const stats = getStats()
    expect(stats.totalScans).toBe(2)
    expect(stats.completedScans).toBe(2)
    expect(stats.totalFindings).toBe(1)
    expect(stats.uniqueTargets).toBe(2)
  })
})

describe('getRecentScans', () => {
  it('returns scans sorted with active first', () => {
    createScan('s1', 'https://a.com')
    updateScanStatus('s1', 'completed')
    createScan('s2', 'https://b.com')
    updateScanStatus('s2', 'scanning')

    const recent = getRecentScans()
    expect(recent[0].id).toBe('s2') // scanning first
    expect(recent[1].id).toBe('s1')
  })
})

describe('getScanHistory', () => {
  it('returns completed scan history for a target', () => {
    createScan('s1', 'https://example.com')
    updateScanStatus('s1', 'completed')
    createScan('s2', 'https://example.com')
    updateScanStatus('s2', 'completed')
    createScan('s3', 'https://other.com')
    updateScanStatus('s3', 'completed')

    const history = getScanHistory('https://example.com')
    expect(history).toHaveLength(2)
    expect(history.every(h => h.id !== 's3')).toBe(true)
  })
})
