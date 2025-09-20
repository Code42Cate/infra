-- +goose Up
-- +goose StatementBegin

-- Add creator tracking fields to secrets table
ALTER TABLE "public"."secrets"
    ADD COLUMN IF NOT EXISTS "created_by_user" uuid NULL,
    ADD COLUMN IF NOT EXISTS "created_by_api_key" uuid NULL;

-- Add foreign key constraints
ALTER TABLE "public"."secrets"
    ADD CONSTRAINT "secrets_users_created_by_user"
        FOREIGN KEY ("created_by_user")
            REFERENCES "auth"."users" ("id")
            ON UPDATE NO ACTION
            ON DELETE SET NULL;

ALTER TABLE "public"."secrets"
    ADD CONSTRAINT "secrets_team_api_keys_created_by_api_key"
        FOREIGN KEY ("created_by_api_key")
            REFERENCES "public"."team_api_keys" ("id")
            ON UPDATE NO ACTION
            ON DELETE SET NULL;

-- Create indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_secrets_created_by_user ON public.secrets (created_by_user);
CREATE INDEX IF NOT EXISTS idx_secrets_created_by_api_key ON public.secrets (created_by_api_key);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Drop indexes
DROP INDEX IF EXISTS idx_secrets_created_by_user;
DROP INDEX IF EXISTS idx_secrets_created_by_api_key;

-- Drop foreign key constraints
ALTER TABLE "public"."secrets" DROP CONSTRAINT IF EXISTS "secrets_users_created_by_user";
ALTER TABLE "public"."secrets" DROP CONSTRAINT IF EXISTS "secrets_team_api_keys_created_by_api_key";

-- Drop columns
ALTER TABLE "public"."secrets" DROP COLUMN IF EXISTS "created_by_user";
ALTER TABLE "public"."secrets" DROP COLUMN IF EXISTS "created_by_api_key";

-- +goose StatementEnd
