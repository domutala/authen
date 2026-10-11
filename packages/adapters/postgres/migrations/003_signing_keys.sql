CREATE TABLE authen_signing_keys (
  kid text PRIMARY KEY,
  algorithm text NOT NULL,
  public_jwk jsonb NOT NULL,
  private_key_encrypted text NOT NULL,
  status text NOT NULL CHECK (status IN ('active', 'retiring')),
  created_at timestamptz NOT NULL,
  retired_at timestamptz,
  expires_at timestamptz
);

-- Une seule clé active à la fois.
CREATE UNIQUE INDEX authen_signing_keys_single_active_idx
  ON authen_signing_keys(status) WHERE status = 'active';
