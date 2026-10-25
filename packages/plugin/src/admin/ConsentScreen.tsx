import type React from 'react'

export interface ConsentScreenProps {
  clientName: string
  scope: string
  clientId: string
  redirectUri: string
  codeChallenge: string
  codeChallengeMethod: string
  state: string
  userId: string
  /** Display-friendly scope list derived from raw scope string */
  scopeLabels?: string[]
}

function scopeToLabel(scope: string): string {
  const MAP: Record<string, string> = {
    'posts:read': 'Read posts',
    'posts:write': 'Create and update posts',
    'posts:delete': 'Delete posts',
    'media:read': 'Read media files',
    'media:write': 'Create or update media',
    'users:read': 'Read user profiles',
    openid: 'Confirm your identity',
    profile: 'Access your profile information',
    email: 'Access your email address',
  }
  return MAP[scope] ?? scope
}

function deriveScopeLabels(rawScope: string): string[] {
  if (!rawScope.trim()) return ['Access your Payload CMS instance']
  return rawScope
    .split(/\s+/)
    .filter(Boolean)
    .map(scopeToLabel)
}

export function ConsentScreen({
  clientName,
  scope,
  clientId,
  redirectUri,
  codeChallenge,
  codeChallengeMethod,
  state,
  userId,
  scopeLabels,
}: ConsentScreenProps): React.ReactElement {
  const labels = scopeLabels ?? deriveScopeLabels(scope)

  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{`Authorize ${clientName}`}</title>
        <style>{`
          body { font-family: system-ui, sans-serif; max-width: 480px; margin: 80px auto; padding: 0 1rem; }
          h1 { font-size: 1.25rem; margin-bottom: 0.5rem; }
          .scope-list { list-style: disc; padding-left: 1.5rem; margin: 1rem 0; }
          .note { font-size: 0.85rem; color: #555; background: #f7f7f7; border-left: 3px solid #d0d0d0; padding: 0.6rem 0.8rem; margin: 1rem 0; }
          .actions { display: flex; gap: 0.75rem; margin-top: 1.5rem; }
          .btn { padding: 0.5rem 1.25rem; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; }
          .btn-approve { background: #0070f3; color: #fff; }
          .btn-deny { background: #f0f0f0; color: #333; }
        `}</style>
      </head>
      <body>
        <h1>Authorize <strong>{clientName}</strong></h1>
        <p>
          Approving will let <strong>{clientName}</strong> access your Payload CMS instance{' '}
          <strong>acting as you</strong>. The following will be granted:
        </p>
        <ul className="scope-list">
          {labels.map((label) => (
            <li key={label}>{label}</li>
          ))}
        </ul>
        <p className="note">Only approve applications you trust.</p>
        <form method="POST" action="/api/oauth/consent">
          <input type="hidden" name="client_id" value={clientId} />
          <input type="hidden" name="redirect_uri" value={redirectUri} />
          <input type="hidden" name="code_challenge" value={codeChallenge} />
          <input type="hidden" name="code_challenge_method" value={codeChallengeMethod} />
          <input type="hidden" name="state" value={state} />
          <input type="hidden" name="user_id" value={userId} />
          <input type="hidden" name="scope" value={scope} />
          <div className="actions">
            <button type="submit" name="decision" value="approve" className="btn btn-approve">
              Approve
            </button>
            <button type="submit" name="decision" value="deny" className="btn btn-deny">
              Deny
            </button>
          </div>
        </form>
      </body>
    </html>
  )
}
