package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

type Secret struct {
	ent.Schema
}

func (Secret) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Immutable().Unique().Annotations(entsql.Default("gen_random_uuid()")),

		field.Time("created_at").Immutable().Default(time.Now).Annotations(
			entsql.Default("CURRENT_TIMESTAMP"),
		),
		field.Time("updated_at").Nillable().Optional(),
		field.UUID("team_id", uuid.UUID{}),
		field.String("label").SchemaType(map[string]string{dialect.Postgres: "text"}),
		field.String("description").SchemaType(map[string]string{dialect.Postgres: "text"}).Default(""),
		field.Other("allowlist", pq.StringArray{}).SchemaType(map[string]string{dialect.Postgres: "text[]"}),
		field.UUID("created_by_user", uuid.UUID{}).Nillable().Optional(),
		field.UUID("created_by_api_key", uuid.UUID{}).Nillable().Optional(),
	}
}

func (Secret) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("team", Team.Type).Unique().Required().
			Ref("secrets").
			Field("team_id"),
		edge.From("creator_user", User.Type).Unique().
			Ref("created_secrets").Field("created_by_user"),
		edge.From("creator_api_key", TeamAPIKey.Type).Unique().
			Ref("created_secrets").Field("created_by_api_key"),
	}
}

func (Secret) Annotations() []schema.Annotation {
	return nil
}

func (Secret) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Mixin{},
	}
}
