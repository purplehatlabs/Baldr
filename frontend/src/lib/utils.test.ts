import { describe, expect, it } from 'vitest'
import { meetsMinSeverity } from './utils'

describe('meetsMinSeverity', () => {
  it('returns true when finding severity meets the configured threshold', () => {
    expect(meetsMinSeverity('critical', 'high')).toBe(true)
    expect(meetsMinSeverity('high', 'high')).toBe(true)
  })

  it('returns false when finding severity is below the configured threshold', () => {
    expect(meetsMinSeverity('medium', 'high')).toBe(false)
    expect(meetsMinSeverity('low', 'high')).toBe(false)
    expect(meetsMinSeverity('unknown', 'high')).toBe(false)
  })
})
