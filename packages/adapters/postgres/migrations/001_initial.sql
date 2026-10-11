CREATE TABLE authen_users (
  id text PRIMARY KEY,
  status text NOT NULL CHECK (status IN ('pending', 'active', 'suspended', 'disabled')),
  last_authenticated_at timestamptz,
  disabled_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE TABLE authen_provider_instances (
  id text PRIMARY KEY,
  type text NOT NULL,
  enabled boolean NOT NULL,
  configuration_ref text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE TABLE authen_identities (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES authen_users(id),
  provider_instance_id text NOT NULL REFERENCES authen_provider_instances(id),
  provider_subject text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'disabled', 'unlinked')),
  verified_at timestamptz,
  last_used_at timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT authen_identities_provider_subject_key
    UNIQUE (provider_instance_id, provider_subject)
);

CREATE INDEX authen_identities_user_id_idx ON authen_identities(user_id);

CREATE TABLE authen_profiles (
  user_id text PRIMARY KEY REFERENCES authen_users(id),
  display_name text,
  given_name text,
  family_name text,
  avatar_url text,
  locale text,
  timezone text,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE TABLE authen_credentials (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES authen_users(id),
  identity_id text REFERENCES authen_identities(id),
  provider_instance_id text NOT NULL REFERENCES authen_provider_instances(id),
  type text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),
  secret_ref text,
  public_data jsonb NOT NULL DEFAULT '{}'::jsonb,
  expires_at timestamptz,
  last_used_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE INDEX authen_credentials_user_id_idx ON authen_credentials(user_id);

CREATE TABLE authen_sessions (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES authen_users(id),
  status text NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),
  context jsonb NOT NULL,
  device jsonb NOT NULL,
  authenticated_at timestamptz NOT NULL,
  last_activity_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  revocation_reason text,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE INDEX authen_sessions_user_id_idx ON authen_sessions(user_id);

CREATE TABLE authen_authentication_transactions (
  id text PRIMARY KEY,
  provider_instance_id text NOT NULL REFERENCES authen_provider_instances(id),
  client_id text,
  user_id text REFERENCES authen_users(id),
  purpose text NOT NULL CHECK (purpose IN ('sign_in', 'sign_up', 'link_identity', 'step_up', 'recovery')),
  status text NOT NULL CHECK (status IN ('pending', 'waiting', 'completed', 'failed', 'expired', 'cancelled')),
  current_step text NOT NULL,
  attempts integer NOT NULL CHECK (attempts >= 0),
  max_attempts integer NOT NULL CHECK (max_attempts > 0),
  state_hash text,
  challenge_ref text,
  expires_at timestamptz NOT NULL,
  completed_at timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE INDEX authen_auth_transactions_user_id_idx
  ON authen_authentication_transactions(user_id);

CREATE TABLE authen_token_families (
  id text PRIMARY KEY,
  session_id text NOT NULL REFERENCES authen_sessions(id),
  client_id text NOT NULL,
  scopes jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  revocation_reason text
);

CREATE INDEX authen_token_families_session_id_idx
  ON authen_token_families(session_id);

CREATE TABLE authen_refresh_tokens (
  id text PRIMARY KEY,
  family_id text NOT NULL REFERENCES authen_token_families(id),
  token_hash text NOT NULL UNIQUE,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  revoked_at timestamptz,
  replaced_by_token_id text REFERENCES authen_refresh_tokens(id)
);

CREATE INDEX authen_refresh_tokens_family_id_idx
  ON authen_refresh_tokens(family_id);
