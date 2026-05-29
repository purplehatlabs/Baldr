import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { AlertCircle, Pencil, Plus, Shield, Trash2 } from 'lucide-react'
import {
  createPolicy,
  deletePolicy,
  listPolicies,
  updatePolicy,
  type Policy,
  type PolicyInput,
} from '@/api/policies'
import type { Severity } from '@/api/findings'
import { EmptyState } from '@/components/shared/EmptyState'
import { PageSpinner } from '@/components/shared/Spinner'

const defaultForm: PolicyInput = {
  name: '',
  description: '',
  enabled: true,
  severity_threshold: 'high',
  risk_score_threshold: 60,
  sla_hours: 72,
}

function useSeverityOptions() {
  const { t } = useTranslation()
  return useMemo(
    () =>
      (['critical', 'high', 'medium', 'low', 'unknown'] as Severity[]).map((value) => ({
        value,
        label: t(`findings.severity.${value}`),
      })),
    [t],
  )
}

export default function PoliciesPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null)

  const { data: policies = [], isLoading } = useQuery({
    queryKey: ['policies'],
    queryFn: listPolicies,
  })

  const createMutation = useMutation({
    mutationFn: createPolicy,
    onSuccess: () => {
      setShowCreate(false)
      queryClient.invalidateQueries({ queryKey: ['policies'] })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: PolicyInput }) => updatePolicy(id, payload),
    onSuccess: () => {
      setEditingPolicy(null)
      queryClient.invalidateQueries({ queryKey: ['policies'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: deletePolicy,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['policies'] }),
  })

  const deletingId = deleteMutation.isPending ? deleteMutation.variables : undefined
  const sorted = useMemo(
    () => [...policies].sort((a, b) => Number(b.enabled) - Number(a.enabled)),
    [policies],
  )

  if (isLoading) return <PageSpinner />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h2 className="text-lg font-semibold text-gray-900">{t('policies.title')}</h2>
          <p className="text-sm text-gray-500">{t('policies.description')}</p>
        </div>
        <button
          onClick={() => {
            setEditingPolicy(null)
            setShowCreate(true)
          }}
          className="inline-flex items-center gap-1.5 px-4 py-2 bg-brand-600 text-white rounded-lg text-sm font-medium hover:bg-brand-700 transition-colors"
        >
          <Plus className="w-4 h-4" />
          {t('policies.newPolicy')}
        </button>
      </div>

      {showCreate && (
        <PolicyForm
          title={t('policies.createTitle')}
          initial={defaultForm}
          submitting={createMutation.isPending}
          onSubmit={(payload) => createMutation.mutate(payload)}
          onCancel={() => setShowCreate(false)}
          error={extractError(createMutation.error)}
        />
      )}

      {editingPolicy && (
        <PolicyForm
          title={t('policies.editTitle', { name: editingPolicy.name })}
          initial={{
            name: editingPolicy.name,
            description: editingPolicy.description ?? '',
            enabled: editingPolicy.enabled,
            severity_threshold: editingPolicy.severity_threshold ?? 'high',
            risk_score_threshold: editingPolicy.risk_score_threshold ?? 60,
            sla_hours: editingPolicy.sla_hours ?? 72,
          }}
          submitting={updateMutation.isPending}
          onSubmit={(payload) => updateMutation.mutate({ id: editingPolicy.id, payload })}
          onCancel={() => setEditingPolicy(null)}
          error={extractError(updateMutation.error)}
        />
      )}

      {sorted.length === 0 ? (
        <div className="bg-white rounded-xl border border-gray-200">
          <EmptyState
            icon={Shield}
            title={t('policies.emptyTitle')}
            description={t('policies.emptyDescription')}
          />
        </div>
      ) : (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100 bg-gray-50">
                <th className="px-5 py-3 text-left font-medium text-gray-500">{t('policies.columns.name')}</th>
                <th className="px-5 py-3 text-left font-medium text-gray-500">{t('policies.columns.minSeverity')}</th>
                <th className="px-5 py-3 text-left font-medium text-gray-500">{t('policies.columns.minRiskScore')}</th>
                <th className="px-5 py-3 text-left font-medium text-gray-500">{t('policies.columns.slaHours')}</th>
                <th className="px-5 py-3 text-left font-medium text-gray-500">{t('policies.columns.status')}</th>
                <th className="px-5 py-3 text-right font-medium text-gray-500">{t('policies.columns.actions')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {sorted.map((policy) => (
                <tr key={policy.id} className="hover:bg-gray-50 transition-colors">
                  <td className="px-5 py-3">
                    <p className="font-medium text-gray-900">{policy.name}</p>
                    {policy.description && (
                      <p className="text-xs text-gray-500 mt-0.5">{policy.description}</p>
                    )}
                  </td>
                  <td className="px-5 py-3 text-gray-600">{policy.severity_threshold ?? '—'}</td>
                  <td className="px-5 py-3 text-gray-600">{policy.risk_score_threshold ?? '—'}</td>
                  <td className="px-5 py-3 text-gray-600">{policy.sla_hours ?? '—'}</td>
                  <td className="px-5 py-3">
                    <span
                      className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium ring-1 ring-inset ${
                        policy.enabled
                          ? 'bg-green-50 text-green-700 ring-green-200'
                          : 'bg-gray-100 text-gray-500 ring-gray-200'
                      }`}
                    >
                      {policy.enabled ? t('policies.active') : t('policies.inactive')}
                    </span>
                  </td>
                  <td className="px-5 py-3">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => {
                          setShowCreate(false)
                          setEditingPolicy(policy)
                        }}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-700 border border-gray-200 rounded-lg hover:bg-gray-50"
                      >
                        <Pencil className="w-3.5 h-3.5" />
                        {t('common.edit')}
                      </button>
                      <button
                        onClick={() => deleteMutation.mutate(policy.id)}
                        disabled={deleteMutation.isPending && deletingId === policy.id}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs text-red-600 border border-red-200 rounded-lg hover:bg-red-50 disabled:opacity-50"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        {t('common.remove')}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function PolicyForm({
  title,
  initial,
  submitting,
  error,
  onSubmit,
  onCancel,
}: {
  title: string
  initial: PolicyInput
  submitting: boolean
  error?: string
  onSubmit: (payload: PolicyInput) => void
  onCancel: () => void
}) {
  const { t } = useTranslation()
  const severityOptions = useSeverityOptions()
  const [name, setName] = useState(initial.name)
  const [description, setDescription] = useState(initial.description ?? '')
  const [enabled, setEnabled] = useState(initial.enabled)
  const [severityThreshold, setSeverityThreshold] = useState<Severity>(initial.severity_threshold ?? 'high')
  const [riskScoreThreshold, setRiskScoreThreshold] = useState(String(initial.risk_score_threshold ?? 60))
  const [slaHours, setSlaHours] = useState(String(initial.sla_hours ?? 72))

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault()
    const normalizedSla = Number(slaHours)
    const normalizedRiskScore = Number(riskScoreThreshold)

    onSubmit({
      name: name.trim(),
      description: description.trim() || undefined,
      enabled,
      severity_threshold: severityThreshold,
      risk_score_threshold: Number.isFinite(normalizedRiskScore) ? normalizedRiskScore : undefined,
      sla_hours: Number.isFinite(normalizedSla) ? normalizedSla : undefined,
    })
  }

  return (
    <form onSubmit={handleSubmit} className="bg-white rounded-xl border border-gray-200 p-5 space-y-4">
      <h3 className="font-medium text-gray-900">{title}</h3>
      <div className="grid grid-cols-2 gap-4">
        <div className="col-span-2">
          <label className="block text-xs font-medium text-gray-700 mb-1">{t('policies.form.name')}</label>
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            required
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
        </div>
        <div className="col-span-2">
          <label className="block text-xs font-medium text-gray-700 mb-1">{t('policies.form.description')}</label>
          <textarea
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            rows={2}
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">{t('policies.form.minSeverity')}</label>
          <select
            value={severityThreshold}
            onChange={(event) => setSeverityThreshold(event.target.value as Severity)}
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            {severityOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">{t('policies.form.minRiskScore')}</label>
          <input
            type="number"
            min={0}
            max={100}
            value={riskScoreThreshold}
            onChange={(event) => setRiskScoreThreshold(event.target.value)}
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">{t('policies.form.slaHours')}</label>
          <input
            type="number"
            min={1}
            value={slaHours}
            onChange={(event) => setSlaHours(event.target.value)}
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
        </div>
      </div>
      <label className="inline-flex items-center gap-2 text-sm text-gray-700">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(event) => setEnabled(event.target.checked)}
          className="h-4 w-4 rounded border-gray-300 text-brand-600 focus:ring-brand-500"
        />
        {t('policies.form.enabled')}
      </label>
      {error && (
        <p className="text-xs text-red-600 flex items-center gap-1">
          <AlertCircle className="w-3.5 h-3.5" />
          {error}
        </p>
      )}
      <div className="flex items-center justify-end gap-2">
        <button
          type="button"
          onClick={onCancel}
          className="px-4 py-2 text-sm text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
        >
          {t('common.cancel')}
        </button>
        <button
          type="submit"
          disabled={submitting || !name.trim()}
          className="px-4 py-2 bg-brand-600 text-white rounded-lg text-sm font-medium hover:bg-brand-700 transition-colors disabled:opacity-50"
        >
          {submitting ? t('common.saving') : t('common.save')}
        </button>
      </div>
    </form>
  )
}

function extractError(error: unknown): string | undefined {
  return (error as { response?: { data?: { error?: string } } })?.response?.data?.error
}
