import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { AlertCircle, Check, Github, Plug, Send, Trash2 } from 'lucide-react'
import {
  deleteGitHubChecksIntegration,
  deleteJiraIntegration,
  deleteSlackIntegration,
  getGitHubChecksIntegration,
  getJiraIntegration,
  getSlackIntegration,
  updateGitHubChecksIntegration,
  updateJiraIntegration,
  updateSlackIntegration,
} from '@/api/integrations'
import { PageSpinner } from '@/components/shared/Spinner'

export default function IntegrationsPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [feedback, setFeedback] = useState<string | null>(null)

  const slackQuery = useQuery({
    queryKey: ['integrations', 'slack'],
    queryFn: getSlackIntegration,
  })

  const jiraQuery = useQuery({
    queryKey: ['integrations', 'jira'],
    queryFn: getJiraIntegration,
  })

  const checksQuery = useQuery({
    queryKey: ['integrations', 'github-checks'],
    queryFn: getGitHubChecksIntegration,
  })

  const slackMutation = useMutation({
    mutationFn: updateSlackIntegration,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations', 'slack'] })
      setFeedback(t('integrations.slackUpdated'))
    },
    onError: () => setFeedback(t('integrations.slackError')),
  })

  const jiraMutation = useMutation({
    mutationFn: updateJiraIntegration,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations', 'jira'] })
      setFeedback(t('integrations.jiraUpdated'))
    },
    onError: () => setFeedback(t('integrations.jiraError')),
  })

  const checksMutation = useMutation({
    mutationFn: updateGitHubChecksIntegration,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations', 'github-checks'] })
      setFeedback(t('integrations.checksUpdated'))
    },
    onError: () => setFeedback(t('integrations.checksError')),
  })

  const resetSlack = useMutation({
    mutationFn: deleteSlackIntegration,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['integrations', 'slack'] }),
  })

  const resetJira = useMutation({
    mutationFn: deleteJiraIntegration,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['integrations', 'jira'] }),
  })

  const resetChecks = useMutation({
    mutationFn: deleteGitHubChecksIntegration,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['integrations', 'github-checks'] }),
  })

  if (slackQuery.isLoading || jiraQuery.isLoading || checksQuery.isLoading) {
    return <PageSpinner />
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold text-gray-900">{t('integrations.title')}</h2>
        <p className="text-sm text-gray-500">{t('integrations.description')}</p>
      </div>

      {feedback && (
        <div className="rounded-lg border border-blue-200 bg-blue-50 text-blue-900 text-sm px-4 py-2 flex items-center justify-between">
          <span>{feedback}</span>
          <button onClick={() => setFeedback(null)} className="text-blue-700 hover:text-blue-900">
            {t('integrations.close')}
          </button>
        </div>
      )}

      <SlackSection
        initial={slackQuery.data ?? { enabled: false }}
        pending={slackMutation.isPending}
        resetting={resetSlack.isPending}
        onSave={slackMutation.mutate}
        onReset={() => resetSlack.mutate()}
      />

      <JiraSection
        initial={jiraQuery.data ?? { enabled: false }}
        pending={jiraMutation.isPending}
        resetting={resetJira.isPending}
        onSave={jiraMutation.mutate}
        onReset={() => resetJira.mutate()}
      />

      <GitHubChecksSection
        initial={checksQuery.data ?? { enabled: false }}
        pending={checksMutation.isPending}
        resetting={resetChecks.isPending}
        onSave={checksMutation.mutate}
        onReset={() => resetChecks.mutate()}
      />
    </div>
  )
}

function SlackSection({
  initial,
  pending,
  resetting,
  onSave,
  onReset,
}: {
  initial: { enabled: boolean; webhook_url?: string; channel?: string }
  pending: boolean
  resetting: boolean
  onSave: (payload: { enabled: boolean; webhook_url?: string; channel?: string }) => void
  onReset: () => void
}) {
  const { t } = useTranslation()
  const [enabled, setEnabled] = useState(initial.enabled)
  const [webhookUrl, setWebhookUrl] = useState(initial.webhook_url ?? '')
  const [channel, setChannel] = useState(initial.channel ?? '')

  return (
    <section className="bg-white rounded-xl border border-gray-200 p-5 space-y-4">
      <header className="flex items-center gap-2">
        <Send className="w-4 h-4 text-gray-500" />
        <h3 className="font-medium text-gray-900">{t('integrations.slack.title')}</h3>
      </header>
      <div className="grid grid-cols-2 gap-4">
        <div className="col-span-2">
          <label className="block text-xs font-medium text-gray-700 mb-1">{t('integrations.slack.webhookUrl')}</label>
          <input
            type="url"
            value={webhookUrl}
            onChange={(event) => setWebhookUrl(event.target.value)}
            placeholder="https://hooks.slack.com/services/..."
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">{t('integrations.slack.defaultChannel')}</label>
          <input
            value={channel}
            onChange={(event) => setChannel(event.target.value)}
            placeholder="#security"
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2"
          />
        </div>
        <div className="flex items-end">
          <label className="inline-flex items-center gap-2 text-sm text-gray-700">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(event) => setEnabled(event.target.checked)}
              className="h-4 w-4 rounded border-gray-300 text-brand-600 focus:ring-brand-500"
            />
            {t('integrations.slack.enabled')}
          </label>
        </div>
      </div>
      <SectionActions
        pending={pending}
        resetting={resetting}
        onSave={() =>
          onSave({
            enabled,
            webhook_url: webhookUrl.trim() || undefined,
            channel: channel.trim() || undefined,
          })
        }
        onReset={onReset}
      />
    </section>
  )
}

function JiraSection({
  initial,
  pending,
  resetting,
  onSave,
  onReset,
}: {
  initial: {
    enabled: boolean
    base_url?: string
    project_key?: string
    email?: string
    api_token?: string
  }
  pending: boolean
  resetting: boolean
  onSave: (payload: {
    enabled: boolean
    base_url?: string
    project_key?: string
    email?: string
    api_token?: string
  }) => void
  onReset: () => void
}) {
  const { t } = useTranslation()
  const [enabled, setEnabled] = useState(initial.enabled)
  const [baseUrl, setBaseUrl] = useState(initial.base_url ?? '')
  const [projectKey, setProjectKey] = useState(initial.project_key ?? '')
  const [email, setEmail] = useState(initial.email ?? '')
  const [token, setToken] = useState('')

  return (
    <section className="bg-white rounded-xl border border-gray-200 p-5 space-y-4">
      <header className="flex items-center gap-2">
        <Plug className="w-4 h-4 text-gray-500" />
        <h3 className="font-medium text-gray-900">{t('integrations.jira.title')}</h3>
      </header>
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">{t('integrations.jira.baseUrl')}</label>
          <input
            type="url"
            value={baseUrl}
            onChange={(event) => setBaseUrl(event.target.value)}
            placeholder="https://company.atlassian.net"
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">{t('integrations.jira.projectKey')}</label>
          <input
            value={projectKey}
            onChange={(event) => setProjectKey(event.target.value)}
            placeholder="SEC"
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">{t('integrations.jira.email')}</label>
          <input
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">{t('integrations.jira.apiToken')}</label>
          <input
            type="password"
            value={token}
            onChange={(event) => setToken(event.target.value)}
            placeholder={t('integrations.jira.keepToken')}
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2"
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
        {t('integrations.jira.enabled')}
      </label>
      <SectionActions
        pending={pending}
        resetting={resetting}
        onSave={() =>
          onSave({
            enabled,
            base_url: baseUrl.trim() || undefined,
            project_key: projectKey.trim() || undefined,
            email: email.trim() || undefined,
            api_token: token.trim() || undefined,
          })
        }
        onReset={onReset}
      />
    </section>
  )
}

function GitHubChecksSection({
  initial,
  pending,
  resetting,
  onSave,
  onReset,
}: {
  initial: { enabled: boolean; check_name?: string; only_on_default_branch?: boolean }
  pending: boolean
  resetting: boolean
  onSave: (payload: { enabled: boolean; check_name?: string; only_on_default_branch?: boolean }) => void
  onReset: () => void
}) {
  const { t } = useTranslation()
  const [enabled, setEnabled] = useState(initial.enabled)
  const [checkName, setCheckName] = useState(initial.check_name ?? 'devsecops/triage')
  const [onlyDefaultBranch, setOnlyDefaultBranch] = useState(initial.only_on_default_branch ?? true)

  return (
    <section className="bg-white rounded-xl border border-gray-200 p-5 space-y-4">
      <header className="flex items-center gap-2">
        <Github className="w-4 h-4 text-gray-500" />
        <h3 className="font-medium text-gray-900">{t('integrations.githubChecks.title')}</h3>
      </header>
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">{t('integrations.githubChecks.checkName')}</label>
          <input
            value={checkName}
            onChange={(event) => setCheckName(event.target.value)}
            className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2"
          />
        </div>
        <div className="flex items-end">
          <label className="inline-flex items-center gap-2 text-sm text-gray-700">
            <input
              type="checkbox"
              checked={onlyDefaultBranch}
              onChange={(event) => setOnlyDefaultBranch(event.target.checked)}
              className="h-4 w-4 rounded border-gray-300 text-brand-600 focus:ring-brand-500"
            />
            {t('integrations.githubChecks.defaultBranchOnly')}
          </label>
        </div>
      </div>
      <label className="inline-flex items-center gap-2 text-sm text-gray-700">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(event) => setEnabled(event.target.checked)}
          className="h-4 w-4 rounded border-gray-300 text-brand-600 focus:ring-brand-500"
        />
        {t('integrations.githubChecks.enabled')}
      </label>
      <SectionActions
        pending={pending}
        resetting={resetting}
        onSave={() =>
          onSave({
            enabled,
            check_name: checkName.trim() || undefined,
            only_on_default_branch: onlyDefaultBranch,
          })
        }
        onReset={onReset}
      />
    </section>
  )
}

function SectionActions({
  pending,
  resetting,
  onSave,
  onReset,
}: {
  pending: boolean
  resetting: boolean
  onSave: () => void
  onReset: () => void
}) {
  const { t } = useTranslation()

  return (
    <div className="flex items-center justify-between gap-2 pt-1">
      <button
        type="button"
        onClick={onReset}
        disabled={resetting}
        className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm text-red-600 border border-red-200 rounded-lg hover:bg-red-50 disabled:opacity-50"
      >
        <Trash2 className="w-3.5 h-3.5" />
        {t('integrations.clear')}
      </button>
      <button
        type="button"
        onClick={onSave}
        disabled={pending}
        className="inline-flex items-center gap-1.5 px-4 py-2 bg-brand-600 text-white rounded-lg text-sm font-medium hover:bg-brand-700 disabled:opacity-50"
      >
        {pending ? (
          <>
            <AlertCircle className="w-3.5 h-3.5" />
            {t('common.saving')}
          </>
        ) : (
          <>
            <Check className="w-3.5 h-3.5" />
            {t('common.save')}
          </>
        )}
      </button>
    </div>
  )
}
