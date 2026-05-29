import { describe, expect, it } from 'vitest'
import { DEFAULT_LOCALE, normalizeLocale } from './languages'

describe('normalizeLocale', () => {
  it('defaults to en', () => {
    expect(normalizeLocale(null)).toBe(DEFAULT_LOCALE)
    expect(normalizeLocale(undefined)).toBe(DEFAULT_LOCALE)
    expect(normalizeLocale('')).toBe(DEFAULT_LOCALE)
  })

  it('normalizes pt-BR variants', () => {
    expect(normalizeLocale('pt-BR')).toBe('pt-BR')
    expect(normalizeLocale('pt-br')).toBe('pt-BR')
    expect(normalizeLocale('pt_br')).toBe('pt-BR')
  })
})
