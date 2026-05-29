import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { AlertCircle, FileWarning, Save } from 'lucide-react'
import { createManualFinding, type CreateManualFindingInput, type Severity } from '@/api/findings'
import { useAuth } from '@/hooks/useAuth'
import { PageSpinner } from '@/components/shared/Spinner'
import { cn } from '@/lib/utils'

export default function ManualVulnerabilitiesPage() {
  const { t } = useTranslation()
  const { user, isLoading } = useAuth()
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const severities = useMemo(
    () =>
      (['critical', 'high', 'medium', 'low', 'unknown'] as Severity[]).map((value) => ({
        value,
        label: t(`findings.severity.${value}`),
      })),
    [t],
  )

  const externalSources = useMemo(
    () => [
      { value: '', label: t('manualVulnerabilities.fields.selectSource') },
      { value: 'bug_bounty', label: t('manualVulnerabilities.sources.bug_bounty') },
      { value: 'pentest', label: t('manualVulnerabilities.sources.pentest') },
      { value: 'vendor_advisory', label: t('manualVulnerabilities.sources.vendor_advisory') },
      { value: 'internal_audit', label: t('manualVulnerabilities.sources.internal_audit') },
      { value: 'other', label: t('manualVulnerabilities.sources.other') },
    ],
    [t],
  )

  const [summary, setSummary] = useState('')
  const [severity, setSeverity] = useState<Severity>('high')
  const [externalReference, setExternalReference] = useState('')
  const [packageName, setPackageName] = useState('')
  const [packageVersion, setPackageVersion] = useState('')
  const [externalSource, setExternalSource] = useState('')
  const [evidence, setEvidence] = useState('')
  const [businessImpact, setBusinessImpact] = useState('')
  const [details, setDetails] = useState('')
  const [slaDueAt, setSlaDueAt] = useState('')
  const [error, setError] = useState('')

  const createMutation = useMutation({
    mutationFn: (payload: CreateManualFindingInput) => createManualFinding(payload),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
      navigate(`/triage?finding_id=${result.id}`)
    },
    onError: (err: unknown) => {
      const message =
        err && typeof err === 'object' && 'response' in err
          ? String((err as { response?: { data?: { error?: string } } }).response?.data?.error ?? t('manualVulnerabilities.createError'))
          : t('manualVulnerabilities.createError')
      setError(message)
    },
  })

  if (isLoading) return <PageSpinner />

  const canCreate = user?.role === 'admin' || user?.role === 'owner'

  if (!canCreate) {
    return (
      <div className="max-w-2xl mx-auto bg-white rounded-xl border border-gray-200 p-8 text-center">
        <AlertCircle className="w-10 h-10 text-amber-500 mx-auto mb-3" />
        <h2 className="text-lg font-semibold text-gray-900">{t('manualVulnerabilities.accessDeniedTitle')}</h2>
        <p className="text-sm text-gray-500 mt-2">{t('manualVulnerabilities.accessDeniedDescription')}</p>
      </div>
    )
  }

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault()
    setError('')

    if (!summary.trim() || !externalReference.trim()) {
      setError(t('manualVulnerabilities.validationRequired'))
      return
    }

    const payload: CreateManualFindingInput = {
      summary: summary.trim(),
      severity,
      external_reference: externalReference.trim(),
      package_name: packageName.trim() || undefined,
      package_version: packageVersion.trim() || undefined,
      external_source: externalSource || undefined,
      details: details.trim() || undefined,
      business_impact: businessImpact.trim() || undefined,
      sla_due_at: slaDueAt ? new Date(slaDueAt).toISOString() : undefined,
    }

    if (evidence.trim()) {
      try {
        payload.evidence = JSON.parse(evidence) as Record<string, unknown>
      } catch {
        payload.evidence = { notes: evidence.trim() }
      }
    }

    createMutation.mutate(payload)
  }

  return (
    <div className="max-w-3xl space-y-6">
      <div className="flex items-start gap-3">
        <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-brand-50 text-brand-600">
          <FileWarning className="w-5 h-5" />
        </div>
        <div>
          <h1 className="text-xl font-semibold text-gray-900">{t('manualVulnerabilities.title')}</h1>
          <p className="text-sm text-gray-500 mt-1">{t('manualVulnerabilities.description')}</p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="bg-white rounded-xl border border-gray-200 p-6 space-y-5">
        {error && (
          <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Field label={t('manualVulnerabilities.fields.summary')} className="md:col-span-2">
            <input
              value={summary}
              onChange={(e) => setSummary(e.target.value)}
              placeholder={t('manualVulnerabilities.fields.summaryPlaceholder')}
              className={inputClass}
              required
            />
          </Field>

          <Field label={t('manualVulnerabilities.fields.severity')}>
            <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)} className={inputClass}>
              {severities.map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
          </Field>

          <Field label={t('manualVulnerabilities.fields.externalId')}>
            <input
              value={externalReference}
              onChange={(e) => setExternalReference(e.target.value)}
              placeholder="CVE-2024-1234"
              className={cn(inputClass, 'font-mono text-sm')}
              required
            />
          </Field>

          <Field label={t('manualVulnerabilities.fields.package')}>
            <input
              value={packageName}
              onChange={(e) => setPackageName(e.target.value)}
              placeholder="lodash"
              className={inputClass}
            />
          </Field>

          <Field label={t('manualVulnerabilities.fields.version')}>
            <input
              value={packageVersion}
              onChange={(e) => setPackageVersion(e.target.value)}
              placeholder="4.17.21"
              className={inputClass}
            />
          </Field>

          <Field label={t('manualVulnerabilities.fields.externalSource')}>
            <select value={externalSource} onChange={(e) => setExternalSource(e.target.value)} className={inputClass}>
              {externalSources.map((item) => (
                <option key={item.value || 'none'} value={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
          </Field>

          <Field label={t('manualVulnerabilities.fields.slaDue')}>
            <input
              type="datetime-local"
              value={slaDueAt}
              onChange={(e) => setSlaDueAt(e.target.value)}
              className={inputClass}
            />
          </Field>

          <Field label={t('manualVulnerabilities.fields.businessImpact')} className="md:col-span-2">
            <textarea
              value={businessImpact}
              onChange={(e) => setBusinessImpact(e.target.value)}
              rows={2}
              placeholder={t('manualVulnerabilities.fields.businessImpactPlaceholder')}
              className={inputClass}
            />
          </Field>

          <Field label={t('manualVulnerabilities.fields.details')} className="md:col-span-2">
            <textarea
              value={details}
              onChange={(e) => setDetails(e.target.value)}
              rows={3}
              placeholder={t('manualVulnerabilities.fields.detailsPlaceholder')}
              className={inputClass}
            />
          </Field>

          <Field label={t('manualVulnerabilities.fields.evidence')} className="md:col-span-2">
            <textarea
              value={evidence}
              onChange={(e) => setEvidence(e.target.value)}
              rows={4}
              placeholder={t('manualVulnerabilities.fields.evidencePlaceholder')}
              className={cn(inputClass, 'font-mono text-sm')}
            />
          </Field>
        </div>

        <div className="flex items-center justify-end gap-3 pt-2">
          <button
            type="button"
            onClick={() => navigate('/triage')}
            className="px-4 py-2 text-sm rounded-lg border border-gray-200 text-gray-700 hover:bg-gray-50"
          >
            {t('common.cancel')}
          </button>
          <button
            type="submit"
            disabled={createMutation.isPending}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm rounded-lg bg-brand-600 text-white hover:bg-brand-700 disabled:opacity-50"
          >
            <Save className="w-4 h-4" />
            {createMutation.isPending ? t('manualVulnerabilities.creating') : t('manualVulnerabilities.create')}
          </button>
        </div>
      </form>
    </div>
  )
}

function Field({
  label,
  children,
  className,
}: {
  label: string
  children: React.ReactNode
  className?: string
}) {
  return (
    <label className={cn('block space-y-1.5', className)}>
      <span className="text-sm font-medium text-gray-700">{label}</span>
      {children}
    </label>
  )
}

const inputClass =
  'w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500'
