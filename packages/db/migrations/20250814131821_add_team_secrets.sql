-- +goose Up
-- +goose StatementBegin

-- Create "team_secrets" table
CREATE TABLE IF NOT EXISTS "public"."team_secrets"
(
    "id" uuid NOT NULL DEFAULT gen_random_uuid(),
    "secret_prefix" character varying(11) NOT NULL,
    "secret_length" integer NOT NULL,
    "secret_mask_prefix" character varying(5) NOT NULL,
    "secret_mask_suffix" character varying(5) NOT NULL,
    "created_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" timestamptz NULL,
    "team_id" uuid NOT NULL,
    "name" text NOT NULL DEFAULT 'Unnamed Secret',
    "hosts" text[] NOT NULL,
    PRIMARY KEY ("id"),
    CONSTRAINT "team_secrets_teams_team_secrets" FOREIGN KEY ("team_id") REFERENCES "public"."teams" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);

-- Enable RLS
ALTER TABLE "public"."team_secrets" ENABLE ROW LEVEL SECURITY;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Drop table
DROP TABLE IF EXISTS "public"."team_secrets";

-- +goose StatementEnd
