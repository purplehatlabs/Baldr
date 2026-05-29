import { useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  Plus,
  Trash2,
  GitBranch,
  Clock,
  AlertCircle,
  CheckCircle,
  Upload,
  KeyRound,
  Sparkles,
  RefreshCw,
} from 'lucide-react'
import {
  listOrgs,
  createOrg,
  deleteOrg,
  syncOrgMemberships,
  type Org,
  type MembershipSyncResponse,
} from '@/api/orgs'
import { cn } from '@/lib/utils'
import {
  getGitHubAppStatus,
  updateGitHubApp,
  deleteGitHubApp,
  getLLMStatus,
  updateLLM,
  deleteLLM,
  type LLMStatus,
} from '@/api/settings'
import { PageSpinner } from '@/components/shared/Spinner'
import { useAuth } from '@/hooks/useAuth'
import { useLanguage } from '@/hooks/useLanguage'
import { SUPPORTED_LOCALES, type AppLocale } from '@/i18n/languages'
import { getAppLocale } from '@/i18n'
import { formatDateTime } from '@/lib/locale'

export default function SettingsPage() {
  return (
    <div className="max-w-3xl space-y-10">
      <LanguageSection />
      <GithubAppSection />
      <LLMConfigSection />
      <OrgsSection />
    </div>
  )
}

function LanguageSection() {
  const { t } = useTranslation()
  const { user } = useAuth()
  const { locale, changeLanguage, isSaving } = useLanguage()
  const [saved, setSaved] = useState(false)

  const handleChange = (next: AppLocale) => {
    setSaved(false)
    changeLanguage(next)
    setSaved(true)
  }

  return (
    <section className="rounded-xl border border-gray-200 bg-white p-6 space-y-4">
      <div>
        <h2 className="font-semibold text-gray-900">{t('settings.language.title')}</h2>
        <p className="text-sm text-gray-500 mt-0.5">{t('settings.language.description')}</p>
      </div>
      <label className="block space-y-1.5">
        <span className="text-sm font-medium text-gray-700">{t('settings.language.label')}</span>
        <select
          value={user?.language ?? locale}
          onChange={(e) => handleChange(e.target.value as AppLocale)}
          disabled={isSaving}
          className="w-full max-w-xs rounded-lg border border-gray-300 px-3 py-2 text-sm"
        >
          {SUPPORTED_LOCALES.map((code) => (
            <option key={code} value={code}>
              {code === 'en' ? t('settings.language.en') : t('settings.language.ptBR')}
            </option>
          ))}
        </select>
      </label>
      {saved && <p className="text-sm text-green-600">{t('settings.language.saved')}</p>}
    </section>
  )
}

function OrgsSection() {
  const { t } = useTranslation()
  const [showForm, setShowForm] = useState(false)
  const queryClient = useQueryClient()

  const { data: orgs = [], isLoading } = useQuery({
    queryKey: ['orgs'],
    queryFn: listOrgs,
  })

  const deleteMutation = useMutation({
    mutationFn: deleteOrg,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['orgs'] }),
  })

  if (isLoading) return <PageSpinner />

  return (
    <section>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="font-semibold text-gray-900">{t('settings.orgs.title')}</h2>
          <p className="text-sm text-gray-500 mt-0.5">{t('settings.orgs.description')}</p>
        </div>
        <button
          onClick={() => setShowForm(true)}
          className="inline-flex items-center gap-1.5 px-4 py-2 bg-brand-600 text-white rounded-lg text-sm font-medium hover:bg-brand-700 transition-colors"
        >
          <Plus className="w-4 h-4" /> {t('settings.orgs.connect')}
        </button>
      </div>

      {showForm && (
        <AddOrgForm
          onSuccess={() => {
            setShowForm(false)
            queryClient.invalidateQueries({ queryKey: ['orgs'] })
          }}
          onCancel={() => setShowForm(false)}
        />
      )}

      {orgs.length === 0 ? (
        <div className="border border-dashed border-gray-300 rounded-xl px-6 py-10 text-center">
          <GitBranch className="w-8 h-8 text-gray-300 mx-auto mb-3" />
          <p className="text-sm text-gray-500">{t('settings.orgs.empty')}</p>
        </div>
      ) : (
        <div className="space-y-3">
          {orgs.map((org) => (
            <OrgCard
              key={org.id}
              org={org}
              onDelete={() => deleteMutation.mutate(org.id)}
              deleting={deleteMutation.isPending && deleteMutation.variables === org.id}
            />
          ))}
        </div>
      )}
    </section>
  )
}

function OrgCard({ org, onDelete, deleting }: { org: Org; onDelete: () => void; deleting: boolean }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [syncSuccess, setSyncSuccess] = useState<MembershipSyncResponse | null>(null)
  const [syncError, setSyncError] = useState<string | null>(null)

  const syncMutation = useMutation({
    mutationFn: () => syncOrgMemberships(org.id),
    onMutate: () => {
      setSyncError(null)
      setSyncSuccess(null)
    },
    onSuccess: (data) => {
      setSyncSuccess(data)
      void queryClient.invalidateQueries({ queryKey: ['teams'] })
      void queryClient.invalidateQueries({ queryKey: ['team-members'] })
    },
    onError: (err: unknown) => {
      const axiosData = (err as { response?: { data?: unknown } })?.response?.data
      let msg = t('settings.orgs.syncFailed')
      if (axiosData && typeof axiosData === 'object' && axiosData !== null) {
        const d = axiosData as { error?: string; message?: string }
        if (typeof d.error === 'string' && d.error) msg = d.error
        else if (typeof d.message === 'string' && d.message) msg = d.message
      }
      setSyncError(msg)
    },
  })

  const hasInstallation = org.github_app_installation_id != null
  const showSyncFeedback = syncSuccess !== null || syncError !== null

  return (
    <div className="bg-white rounded-xl border border-gray-200">
      <div className="flex items-center gap-4 px-5 py-4">
        <div className="w-9 h-9 rounded-lg bg-gray-100 flex items-center justify-center flex-shrink-0">
          <GitBranch className="w-4 h-4 text-gray-500" />
        </div>
        <div className="flex-1 min-w-0">
          <p className="font-medium text-gray-900">{org.github_org_login}</p>
          <div className="flex items-center gap-3 mt-0.5">
            <span className="text-xs text-gray-500 flex items-center gap-1">
              <Clock className="w-3 h-3" /> {org.scan_cron}
            </span>
            {org.github_app_installation_id ? (
              <span className="text-xs text-green-600 flex items-center gap-1">
                <CheckCircle className="w-3 h-3" /> {t('settings.orgs.appInstalled')}
              </span>
            ) : (
              <span className="text-xs text-yellow-600 flex items-center gap-1">
                <AlertCircle className="w-3 h-3" /> {t('settings.orgs.appNotInstalled')}
              </span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-1 flex-shrink-0">
          {hasInstallation && (
            <button
              type="button"
              onClick={() => syncMutation.mutate()}
              disabled={syncMutation.isPending}
              className="p-2 rounded-lg text-gray-400 hover:text-brand-600 hover:bg-brand-50 transition-colors disabled:opacity-50"
              title={t('settings.orgs.syncMembers')}
              aria-label={t('settings.orgs.syncMembers')}
            >
              <RefreshCw
                className={cn('w-4 h-4', syncMutation.isPending && 'animate-spin')}
              />
            </button>
          )}
          <button
            onClick={onDelete}
            disabled={deleting}
            className="p-2 rounded-lg text-gray-400 hover:text-red-600 hover:bg-red-50 transition-colors"
            title={t('settings.orgs.removeOrg')}
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>
      {showSyncFeedback && (
        <div className="border-t border-gray-100 px-5 py-2.5">
          {syncSuccess && (
            <p className="text-xs text-green-600 flex items-center gap-1.5">
              <CheckCircle className="w-3.5 h-3.5 shrink-0" />
              {t('settings.orgs.syncSuccess', { orgMembers: syncSuccess.org_members_upserted, teamLinks: syncSuccess.team_links_upserted, teams: syncSuccess.teams_processed })}
            </p>
          )}
          {syncError && (
            <p className="text-xs text-red-600 flex items-center gap-1.5">
              <AlertCircle className="w-3.5 h-3.5 shrink-0" />
              {syncError}
            </p>
          )}
        </div>
      )}
    </div>
  )
}

function AddOrgForm({ onSuccess, onCancel }: { onSuccess: () => void; onCancel: () => void }) {
  const { t } = useTranslation()
  const [login, setLogin] = useState('')
  const [installationId, setInstallationId] = useState('')
  const [cron, setCron] = useState('0 2 * * *')
  const [error, setError] = useState('')

  const mutation = useMutation({
    mutationFn: createOrg,
    onSuccess,
    onError: () => setError(t('settings.orgs.connectError')),
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    mutation.mutate({
      github_org_login: login.trim(),
      github_app_installation_id: installationId ? Number(installationId) : undefined,
      scan_cron: cron,
    })
  }

  return (
    <form onSubmit={handleSubmit} className="bg-gray-50 border border-gray-200 rounded-xl p-5 mb-4 space-y-4">
      <h3 className="font-medium text-gray-900 text-sm">{t('settings.orgs.newOrg')}</h3>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            {t('settings.orgs.orgLogin')}
          </label>
          <input
            type="text"
            value={login}
            onChange={(e) => setLogin(e.target.value)}
            placeholder="my-company"
            required
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            {t('settings.orgs.installationId')}
          </label>
          <input
            type="number"
            value={installationId}
            onChange={(e) => setInstallationId(e.target.value)}
            placeholder="12345678"
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
        </div>
      </div>

      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          {t('settings.orgs.scanCron')} <span className="text-gray-400 font-normal">{t('settings.orgs.scanCronHint')}</span>
        </label>
        <input
          type="text"
          value={cron}
          onChange={(e) => setCron(e.target.value)}
          placeholder="0 2 * * *"
          className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500 font-mono"
        />
      </div>

      {error && (
        <p className="text-xs text-red-600 flex items-center gap-1">
          <AlertCircle className="w-3.5 h-3.5" /> {error}
        </p>
      )}

      <div className="flex gap-2 justify-end">
        <button
          type="button"
          onClick={onCancel}
          className="px-4 py-2 text-sm text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
        >
          {t('common.cancel')}
        </button>
        <button
          type="submit"
          disabled={mutation.isPending || !login}
          className="px-4 py-2 bg-brand-600 text-white rounded-lg text-sm font-medium hover:bg-brand-700 transition-colors disabled:opacity-50"
        >
          {mutation.isPending ? t('common.connecting') : t('common.connect')}
        </button>
      </div>
    </form>
  )
}

function GithubAppSection() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { data: status, isLoading } = useQuery({
    queryKey: ['settings', 'github-app'],
    queryFn: getGitHubAppStatus,
  })

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ['settings', 'github-app'] })

  return (
    <section>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="font-semibold text-gray-900">{t('settings.githubApp.title')}</h2>
          <p className="text-sm text-gray-500 mt-0.5">{t('settings.githubApp.descriptionFull')}</p>
        </div>
      </div>

      {isLoading ? (
        <PageSpinner />
      ) : status?.configured ? (
        <ConfiguredCard status={status} onChange={invalidate} />
      ) : (
        <UploadForm onSuccess={invalidate} />
      )}

      <ol className="mt-6 space-y-2 text-xs text-gray-500">
        {(t('settings.githubApp.setupSteps', { returnObjects: true }) as string[]).map((step, i) => (
          <li key={i} className="flex gap-2">
            <span className="font-medium text-gray-400">{i + 1}.</span>
            <span>{step}</span>
          </li>
        ))}
      </ol>
    </section>
  )
}

function ConfiguredCard({
  status,
  onChange,
}: {
  status: { app_id?: number; updated_at?: string }
  onChange: () => void
}) {
  const { t } = useTranslation()
  const [confirmRemove, setConfirmRemove] = useState(false)
  const [showReplace, setShowReplace] = useState(false)

  const removeMutation = useMutation({
    mutationFn: deleteGitHubApp,
    onSuccess: () => {
      setConfirmRemove(false)
      onChange()
    },
  })

  if (showReplace) {
    return (
      <UploadForm
        onSuccess={() => {
          setShowReplace(false)
          onChange()
        }}
        onCancel={() => setShowReplace(false)}
      />
    )
  }

  return (
    <div className="flex items-center gap-4 px-5 py-4 bg-white rounded-xl border border-gray-200">
      <div className="w-9 h-9 rounded-lg bg-green-50 flex items-center justify-center flex-shrink-0">
        <KeyRound className="w-4 h-4 text-green-600" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="font-medium text-gray-900 flex items-center gap-2">
          App ID {status.app_id}
          <span className="inline-flex items-center gap-1 text-xs font-normal text-green-600">
            <CheckCircle className="w-3 h-3" /> {t('settings.githubApp.configured')}
          </span>
        </p>
        {status.updated_at && (
          <p className="text-xs text-gray-500 mt-0.5">
            {t('common.updatedAt', { value: formatDateTime(status.updated_at, getAppLocale()) })}
          </p>
        )}
      </div>
      <button
        onClick={() => setShowReplace(true)}
        className="px-3 py-1.5 text-sm text-gray-700 border border-gray-200 hover:bg-gray-50 rounded-lg transition-colors"
      >
        {t('settings.githubApp.replace')}
      </button>
      {confirmRemove ? (
        <>
          <button
            onClick={() => removeMutation.mutate()}
            disabled={removeMutation.isPending}
            className="px-3 py-1.5 text-sm text-white bg-red-600 hover:bg-red-700 rounded-lg transition-colors disabled:opacity-50"
          >
            {removeMutation.isPending ? t('common.removing') : t('common.confirm')}
          </button>
          <button
            onClick={() => setConfirmRemove(false)}
            className="px-3 py-1.5 text-sm text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
          >
            {t('common.cancel')}
          </button>
        </>
      ) : (
        <button
          onClick={() => setConfirmRemove(true)}
          className="p-2 rounded-lg text-gray-400 hover:text-red-600 hover:bg-red-50 transition-colors"
          title={t('settings.githubApp.removeConfig')}
        >
          <Trash2 className="w-4 h-4" />
        </button>
      )}
    </div>
  )
}

function UploadForm({
  onSuccess,
  onCancel,
}: {
  onSuccess: () => void
  onCancel?: () => void
}) {
  const { t } = useTranslation()
  const [appId, setAppId] = useState('')
  const [pem, setPem] = useState('')
  const [error, setError] = useState('')
  const fileRef = useRef<HTMLInputElement | null>(null)

  const mutation = useMutation({
    mutationFn: updateGitHubApp,
    onSuccess,
    onError: (err: unknown) => {
      const msg =
        (err as { response?: { data?: { error?: string } } })?.response?.data
          ?.error ?? t('settings.githubApp.saveFailed')
      setError(msg)
    },
  })

  const handleFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setError('')
    const text = await file.text()
    setPem(text)
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    const id = Number(appId)
    if (!id || Number.isNaN(id)) {
      setError(t('settings.githubApp.appIdRequired'))
      return
    }
    if (!pem.includes('PRIVATE KEY')) {
      setError(t('settings.githubApp.invalidPem'))
      return
    }
    mutation.mutate({ app_id: id, private_key: pem })
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="bg-gray-50 border border-gray-200 rounded-xl p-5 space-y-4"
    >
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          {t('settings.githubApp.appId')}
        </label>
        <input
          type="number"
          value={appId}
          onChange={(e) => setAppId(e.target.value)}
          placeholder="123456"
          required
          className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
        />
      </div>

      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          {t('settings.githubApp.privateKey')}
        </label>
        <input
          ref={fileRef}
          type="file"
          accept=".pem,.key,application/x-pem-file"
          onChange={handleFile}
          className="hidden"
        />
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => fileRef.current?.click()}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-sm text-gray-700 border border-gray-200 hover:bg-white rounded-lg transition-colors"
          >
            <Upload className="w-3.5 h-3.5" /> {t('settings.githubApp.selectPem')}
          </button>
          {pem && (
            <span className="text-xs text-green-600 flex items-center gap-1">
              <CheckCircle className="w-3.5 h-3.5" /> {t('settings.githubApp.loaded', { bytes: pem.length })}
            </span>
          )}
        </div>
        <textarea
          value={pem}
          onChange={(e) => setPem(e.target.value)}
          placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----"
          rows={6}
          className="mt-2 w-full text-xs font-mono border border-gray-200 rounded-lg px-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
        />
        <p className="text-xs text-gray-500 mt-1">
          {t('settings.githubApp.pemHint')}
        </p>
      </div>

      {error && (
        <p className="text-xs text-red-600 flex items-center gap-1">
          <AlertCircle className="w-3.5 h-3.5" /> {error}
        </p>
      )}

      <div className="flex gap-2 justify-end">
        {onCancel && (
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 text-sm text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
          >
            {t('common.cancel')}
          </button>
        )}
        <button
          type="submit"
          disabled={mutation.isPending || !appId || !pem}
          className="px-4 py-2 bg-brand-600 text-white rounded-lg text-sm font-medium hover:bg-brand-700 transition-colors disabled:opacity-50"
        >
          {mutation.isPending ? t('common.saving') : t('settings.githubApp.saveGithubApp')}
        </button>
      </div>
    </form>
  )
}

function LLMConfigSection() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { data: status, isLoading } = useQuery({
    queryKey: ['settings', 'llm'],
    queryFn: getLLMStatus,
  })

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ['settings', 'llm'] })

  return (
    <section>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="font-semibold text-gray-900">{t('settings.llm.titleFull')}</h2>
          <p className="text-sm text-gray-500 mt-0.5">{t('settings.llm.descriptionFull')}</p>
        </div>
      </div>

      {isLoading ? (
        <PageSpinner />
      ) : status?.configured ? (
        <LLMConfiguredCard status={status} onChange={invalidate} />
      ) : (
        <LLMForm onSuccess={invalidate} />
      )}
    </section>
  )
}

function LLMConfiguredCard({
  status,
  onChange,
}: {
  status: LLMStatus
  onChange: () => void
}) {
  const { t } = useTranslation()
  const [confirmRemove, setConfirmRemove] = useState(false)
  const [showEdit, setShowEdit] = useState(false)

  const removeMutation = useMutation({
    mutationFn: deleteLLM,
    onSuccess: () => {
      setConfirmRemove(false)
      onChange()
    },
  })

  if (showEdit) {
    return (
      <LLMForm
        initial={status}
        onSuccess={() => {
          setShowEdit(false)
          onChange()
        }}
        onCancel={() => setShowEdit(false)}
      />
    )
  }

  return (
    <div className="flex items-center gap-4 px-5 py-4 bg-white rounded-xl border border-gray-200">
      <div className="w-9 h-9 rounded-lg bg-purple-50 flex items-center justify-center flex-shrink-0">
        <Sparkles className="w-4 h-4 text-purple-600" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="font-medium text-gray-900 flex items-center gap-2">
          {status.model}
          <span className="inline-flex items-center gap-1 text-xs font-normal text-green-600">
            <CheckCircle className="w-3 h-3" /> {t('settings.githubApp.configured')}
          </span>
        </p>
        <p className="text-xs text-gray-500 mt-0.5 truncate">
          {status.base_url}
          {status.agentic_model ? ` · agentic: ${status.agentic_model}` : ''}
          {status.translation_model ? ` · translation: ${status.translation_model}` : ''}
          {status.batch_enabled ? ` · ${t('settings.llm.batchEnabled')}` : ''}
          {status.has_api_key ? t('settings.llm.apiKeySaved') : t('settings.llm.noApiKey')}
          {status.timeout_seconds ? t('settings.llm.timeout', { seconds: status.timeout_seconds }) : ''}
          {t('settings.llm.autoAnalysis', { severity: status.auto_analysis_min_severity })}
        </p>
        {status.updated_at && (
          <p className="text-xs text-gray-400 mt-0.5">
            {t('common.updatedAt', { value: formatDateTime(status.updated_at, getAppLocale()) })}
          </p>
        )}
      </div>
      <button
        onClick={() => setShowEdit(true)}
        className="px-3 py-1.5 text-sm text-gray-700 border border-gray-200 hover:bg-gray-50 rounded-lg transition-colors"
      >
        {t('common.edit')}
      </button>
      {confirmRemove ? (
        <>
          <button
            onClick={() => removeMutation.mutate()}
            disabled={removeMutation.isPending}
            className="px-3 py-1.5 text-sm text-white bg-red-600 hover:bg-red-700 rounded-lg transition-colors disabled:opacity-50"
          >
            {removeMutation.isPending ? t('common.removing') : t('common.confirm')}
          </button>
          <button
            onClick={() => setConfirmRemove(false)}
            className="px-3 py-1.5 text-sm text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
          >
            {t('common.cancel')}
          </button>
        </>
      ) : (
        <button
          onClick={() => setConfirmRemove(true)}
          className="p-2 rounded-lg text-gray-400 hover:text-red-600 hover:bg-red-50 transition-colors"
          title={t('settings.githubApp.removeConfig')}
        >
          <Trash2 className="w-4 h-4" />
        </button>
      )}
    </div>
  )
}

function LLMForm({
  initial,
  onSuccess,
  onCancel,
}: {
  initial?: LLMStatus
  onSuccess: () => void
  onCancel?: () => void
}) {
  const { t } = useTranslation()
  const isEditing = Boolean(initial?.configured)
  const [baseUrl, setBaseUrl] = useState(initial?.base_url ?? 'http://litellm:4000')
  const [model, setModel] = useState(initial?.model ?? 'gpt-4o-mini')
  const [agenticModel, setAgenticModel] = useState(initial?.agentic_model ?? '')
  const [translationModel, setTranslationModel] = useState(initial?.translation_model ?? '')
  const [batchEnabled, setBatchEnabled] = useState(initial?.batch_enabled ?? false)
  const [apiKey, setApiKey] = useState('')
  const [clearApiKey, setClearApiKey] = useState(false)
  const [timeout, setTimeout] = useState(String(initial?.timeout_seconds ?? 60))
  const [autoAnalysisMinSeverity, setAutoAnalysisMinSeverity] = useState<
    'critical' | 'high' | 'medium'
  >(initial?.auto_analysis_min_severity ?? 'high')
  const [error, setError] = useState('')

  const mutation = useMutation({
    mutationFn: updateLLM,
    onSuccess,
    onError: (err: unknown) => {
      const msg =
        (err as { response?: { data?: { error?: string } } })?.response?.data
          ?.error ?? t('settings.githubApp.saveFailed')
      setError(msg)
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    const url = baseUrl.trim()
    if (!/^https?:\/\//.test(url)) {
      setError(t('settings.llm.baseUrlRequired'))
      return
    }
    const timeoutSeconds = Number(timeout)
    if (!Number.isFinite(timeoutSeconds) || timeoutSeconds < 5 || timeoutSeconds > 600) {
      setError(t('settings.llm.timeoutRange'))
      return
    }

    let apiKeyField: string | undefined
    if (clearApiKey) {
      apiKeyField = ''
    } else if (apiKey !== '') {
      apiKeyField = apiKey
    } else if (!isEditing) {
      apiKeyField = ''
    }

    mutation.mutate({
      base_url: url,
      model: model.trim(),
      agentic_model: agenticModel.trim() || undefined,
      translation_model: translationModel.trim() || undefined,
      batch_enabled: batchEnabled,
      api_key: apiKeyField,
      timeout_seconds: timeoutSeconds,
      auto_analysis_min_severity: autoAnalysisMinSeverity,
    })
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="bg-gray-50 border border-gray-200 rounded-xl p-5 space-y-4"
    >
      <div className="grid grid-cols-2 gap-4">
        <div className="col-span-2">
          <label className="block text-xs font-medium text-gray-700 mb-1">
            {t('settings.llm.baseUrl')}
          </label>
          <input
            type="url"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="http://litellm:4000  ou  https://api.openai.com"
            required
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
          <p className="text-xs text-gray-500 mt-1">
            {t('settings.llm.baseUrlHint')}
          </p>
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            {t('settings.llm.defaultModel')}
          </label>
          <input
            type="text"
            value={model}
            onChange={(e) => setModel(e.target.value)}
            placeholder="gpt-4o-mini"
            required
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500 font-mono"
          />
          <p className="text-xs text-gray-500 mt-1">{t('settings.llm.defaultModelHint')}</p>
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            {t('settings.llm.agenticModel')}
          </label>
          <input
            type="text"
            value={agenticModel}
            onChange={(e) => setAgenticModel(e.target.value)}
            placeholder={model || 'gpt-4o-mini'}
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500 font-mono"
          />
          <p className="text-xs text-gray-500 mt-1">{t('settings.llm.agenticModelHint')}</p>
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            {t('settings.llm.translationModel')}
          </label>
          <input
            type="text"
            value={translationModel}
            onChange={(e) => setTranslationModel(e.target.value)}
            placeholder={model || 'gpt-4o-mini'}
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500 font-mono"
          />
          <p className="text-xs text-gray-500 mt-1">{t('settings.llm.translationModelHint')}</p>
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            {t('settings.llm.timeoutLabel')}
          </label>
          <input
            type="number"
            min={5}
            max={600}
            value={timeout}
            onChange={(e) => setTimeout(e.target.value)}
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
        </div>

        <div className="col-span-2">
          <label className="flex items-center gap-2 text-sm text-gray-700">
            <input
              type="checkbox"
              checked={batchEnabled}
              onChange={(e) => setBatchEnabled(e.target.checked)}
              className="rounded border-gray-300 text-brand-600 focus:ring-brand-500"
            />
            {t('settings.llm.batchEnabled')}
          </label>
          <p className="text-xs text-gray-500 mt-1">{t('settings.llm.batchEnabledHint')}</p>
        </div>

        <div className="col-span-2">
          <label className="block text-xs font-medium text-gray-700 mb-1">
            {t('settings.llm.autoAnalysisFrom')}
          </label>
          <select
            value={autoAnalysisMinSeverity}
            onChange={(e) =>
              setAutoAnalysisMinSeverity(e.target.value as 'critical' | 'high' | 'medium')
            }
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            <option value="critical">{t('settings.llm.autoAnalysisCritical')}</option>
            <option value="high">{t('settings.llm.autoAnalysisHigh')}</option>
            <option value="medium">{t('settings.llm.autoAnalysisMedium')}</option>
          </select>
          <p className="text-xs text-gray-500 mt-1">
            {t('settings.llm.autoAnalysisHint')}
          </p>
        </div>
      </div>

      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          {t('settings.llm.apiKey')} {isEditing ? t('settings.llm.apiKeyKeep') : '*'}
        </label>
        <input
          type="password"
          value={apiKey}
          onChange={(e) => {
            setApiKey(e.target.value)
            if (e.target.value) setClearApiKey(false)
          }}
          autoComplete="new-password"
          placeholder={isEditing && initial?.has_api_key ? t('settings.llm.apiKeyNoChange') : 'sk-...'}
          className="w-full text-sm font-mono border border-gray-200 rounded-lg px-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
        />
        {isEditing && initial?.has_api_key && (
          <label className="flex items-center gap-2 mt-2 text-xs text-gray-600">
            <input
              type="checkbox"
              checked={clearApiKey}
              onChange={(e) => {
                setClearApiKey(e.target.checked)
                if (e.target.checked) setApiKey('')
              }}
            />
            {t('settings.llm.clearApiKey')}
          </label>
        )}
      </div>

      {error && (
        <p className="text-xs text-red-600 flex items-center gap-1">
          <AlertCircle className="w-3.5 h-3.5" /> {error}
        </p>
      )}

      <div className="flex gap-2 justify-end">
        {onCancel && (
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 text-sm text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
          >
            {t('common.cancel')}
          </button>
        )}
        <button
          type="submit"
          disabled={mutation.isPending || !baseUrl || !model}
          className="px-4 py-2 bg-brand-600 text-white rounded-lg text-sm font-medium hover:bg-brand-700 transition-colors disabled:opacity-50"
        >
          {mutation.isPending ? t('common.saving') : t('settings.llm.saveLlm')}
        </button>
      </div>
    </form>
  )
}
