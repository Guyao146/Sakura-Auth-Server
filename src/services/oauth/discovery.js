import { getRuntime } from '../../core/runtime.js';
import { jwks } from '../../core/keys.js';
import { SCOPES } from '../../core/config.js';
import { sendJson } from '../../core/http.js';

export function discovery(ctx) {
  const base = getRuntime().issuer;
  sendJson(ctx.res, 200, {
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    userinfo_endpoint: `${base}/userinfo`,
    jwks_uri: `${base}/jwks.json`,
    introspection_endpoint: `${base}/introspect`,
    revocation_endpoint: `${base}/revoke`,
    end_session_endpoint: `${base}/logout`,
    scopes_supported: Object.keys(SCOPES),
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    code_challenge_methods_supported: ['S256', 'plain'],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce',
      'preferred_username', 'name', 'email', 'email_verified', 'groups'],
  });
}

export function jwksHandler(ctx) {
  sendJson(ctx.res, 200, jwks());
}
