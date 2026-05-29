const POST_LOGIN_REDIRECT_KEY = 'post_login_redirect'

function sanitizeRedirectPath(value: string | null | undefined): string | null {
  if (!value) {
    return null
  }

  if (
    value === '/' ||
    !value.startsWith('/') ||
    value.startsWith('//') ||
    value.startsWith('/login')
  ) {
    return null
  }

  return value
}

export function buildLoginPath(nextPath: string): string {
  const safeNextPath = sanitizeRedirectPath(nextPath)
  if (!safeNextPath) {
    return '/login'
  }

  return `/login?next=${encodeURIComponent(safeNextPath)}`
}

export function getNextPathFromSearch(search: string): string | null {
  const params = new URLSearchParams(search)
  return sanitizeRedirectPath(params.get('next'))
}

export function savePostLoginRedirect(nextPath: string): void {
  const safeNextPath = sanitizeRedirectPath(nextPath)
  if (!safeNextPath) {
    return
  }

  sessionStorage.setItem(POST_LOGIN_REDIRECT_KEY, safeNextPath)
}

export function popPostLoginRedirect(): string | null {
  const value = sessionStorage.getItem(POST_LOGIN_REDIRECT_KEY)
  sessionStorage.removeItem(POST_LOGIN_REDIRECT_KEY)
  return sanitizeRedirectPath(value)
}
