import { describe, expect, it } from 'vitest'
import { formatDateTime } from './locale'

describe('formatDateTime', () => {
  it('formats using en-US locale', () => {
    const formatted = formatDateTime('2026-05-29T12:00:00.000Z', 'en')
    expect(formatted).toContain('2026')
  })

  it('formats using pt-BR locale', () => {
    const formatted = formatDateTime('2026-05-29T12:00:00.000Z', 'pt-BR')
    expect(formatted).toMatch(/2026|29/)
  })
})
