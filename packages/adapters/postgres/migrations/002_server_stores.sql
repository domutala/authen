CREATE TABLE authen_challenges (
  key text PRIMARY KEY,
  value text NOT NULL,
  expires_at timestamptz NOT NULL
);

CREATE INDEX authen_challenges_expires_at_idx
  ON authen_challenges(expires_at);

CREATE TABLE authen_oauth_clients (
  id text PRIMARY KEY,
  redirect_uris jsonb NOT NULL,
  allowed_scopes jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE TABLE authen_authorization_codes (
  code_hash text PRIMARY KEY,
  client_id text NOT NULL REFERENCES authen_oauth_clients(id),
  user_id text NOT NULL REFERENCES authen_users(id),
  session_id text NOT NULL REFERENCES authen_sessions(id),
  redirect_uri text NOT NULL,
  scopes jsonb NOT NULL,
  code_challenge text NOT NULL,
  nonce text,
  expires_at timestamptz NOT NULL
);

CREATE INDEX authen_authorization_codes_expires_at_idx
  ON authen_authorization_codes(expires_at);
