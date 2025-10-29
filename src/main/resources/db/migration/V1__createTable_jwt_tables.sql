CREATE TABLE jwt_tokens (
                            id BIGSERIAL PRIMARY KEY,
                            user_id BIGINT NOT NULL,
                            token_type VARCHAR(20) NOT NULL,
                            token_value TEXT NOT NULL,
                            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                            revoked BOOLEAN NOT NULL DEFAULT FALSE,
                            revoked_at TIMESTAMP
);

COMMENT ON TABLE jwt_tokens IS 'Stores Access and Refresh JWT tokens for users';
COMMENT ON COLUMN jwt_tokens.user_id IS 'User ID associated with the token';
COMMENT ON COLUMN jwt_tokens.token_type IS 'ACCESS or REFRESH';
COMMENT ON COLUMN jwt_tokens.token_value IS 'The actual JWT string';
COMMENT ON COLUMN jwt_tokens.revoked IS 'Indicates if the token was revoked';
COMMENT ON COLUMN jwt_tokens.revoked_at IS 'Timestamp when the token was revoked';



CREATE TABLE jwt_signing_keys (
                                  id BIGSERIAL PRIMARY KEY,
                                  signing_key TEXT NOT NULL,
                                  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE jwt_signing_keys IS 'Stores JWT signing keys used for token generation';
COMMENT ON COLUMN jwt_signing_keys.signing_key IS 'The secret key or key material used for signing JWTs';
COMMENT ON COLUMN jwt_signing_keys.created_at IS 'Timestamp when the key was created';