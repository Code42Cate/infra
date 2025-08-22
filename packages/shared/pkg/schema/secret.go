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
	}
}

func (Secret) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("team", Team.Type).Unique().Required().
			Ref("secrets").
			Field("team_id"),
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
