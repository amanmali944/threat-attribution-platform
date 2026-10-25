"""002_contract_extensions

Revision ID: 002
Revises: 001
Create Date: 2026-10-20 14:30:00.000000

Adds columns required by Developer A contract change requests CR-01 through CR-07:
- Events: entities (JSON), metadata (JSON)               [CR-07]
- Alerts: detector, detector_version, technique,          [CR-03]
          technique_id, entity_id, score, confidence,
          decision, evidence (JSON)
- Incidents: risk_score, risk_level, layers (JSON),       [CR-04]
             first_seen, last_seen
- Attributions: entry_point (JSON), attack_path (JSON),   [CR-04]
                reached_assets (JSON), blast_radius (JSON),
                dwell_time_seconds, explanation (JSON),
                graph (JSON)
- Attributions: actor_name made nullable                   [CR-05]
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# JSON column with native PostgreSQL JSONB support
json_type = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    # ── Events table: CR-07 ──────────────────────────────────────────────
    op.add_column("events", sa.Column("entities", json_type, nullable=True))
    op.add_column("events", sa.Column("metadata", json_type, nullable=True))

    # ── Alerts table: CR-03 ──────────────────────────────────────────────
    op.add_column("alerts", sa.Column("detector", sa.String(length=64), nullable=True))
    op.add_column("alerts", sa.Column("detector_version", sa.String(length=32), nullable=True))
    op.add_column("alerts", sa.Column("technique", sa.String(length=64), nullable=True))
    op.add_column("alerts", sa.Column("technique_id", sa.String(length=32), nullable=True))
    op.add_column("alerts", sa.Column("entity_id", sa.String(length=64), nullable=True))
    op.add_column("alerts", sa.Column("score", sa.Float(), nullable=True))
    op.add_column("alerts", sa.Column("confidence", sa.Float(), nullable=True))
    op.add_column("alerts", sa.Column("decision", sa.String(length=32), nullable=True))
    op.add_column("alerts", sa.Column("evidence", json_type, nullable=True))

    op.create_index("ix_alerts_detector", "alerts", ["detector"])
    op.create_index("ix_alerts_technique", "alerts", ["technique"])
    op.create_index("ix_alerts_technique_id", "alerts", ["technique_id"])
    op.create_index("ix_alerts_entity_id", "alerts", ["entity_id"])

    # ── Incidents table: CR-04 ───────────────────────────────────────────
    op.add_column("incidents", sa.Column("risk_score", sa.Float(), nullable=True))
    op.add_column("incidents", sa.Column("risk_level", sa.String(length=32), nullable=True))
    op.add_column("incidents", sa.Column("layers", json_type, nullable=True))
    op.add_column("incidents", sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True))
    op.add_column("incidents", sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True))

    op.create_index("ix_incidents_first_seen", "incidents", ["first_seen"])
    op.create_index("ix_incidents_last_seen", "incidents", ["last_seen"])

    # ── Attributions table: CR-04 / CR-05 ────────────────────────────────
    op.add_column("attributions", sa.Column("entry_point", json_type, nullable=True))
    op.add_column("attributions", sa.Column("attack_path", json_type, nullable=True))
    op.add_column("attributions", sa.Column("reached_assets", json_type, nullable=True))
    op.add_column("attributions", sa.Column("blast_radius", json_type, nullable=True))
    op.add_column("attributions", sa.Column("dwell_time_seconds", sa.Float(), nullable=True))
    op.add_column("attributions", sa.Column("explanation", json_type, nullable=True))
    op.add_column("attributions", sa.Column("graph", json_type, nullable=True))
    op.add_column("attributions", sa.Column("method", sa.String(length=64), nullable=True))

    # CR-05: Make actor_name nullable (alter existing column)
    with op.batch_alter_table("attributions") as batch_op:
        batch_op.alter_column("actor_name", existing_type=sa.String(length=128), nullable=True)


def downgrade() -> None:
    # ── Attributions ─────────────────────────────────────────────────────
    with op.batch_alter_table("attributions") as batch_op:
        batch_op.alter_column("actor_name", existing_type=sa.String(length=128), nullable=False)
    op.drop_column("attributions", "method")
    op.drop_column("attributions", "graph")
    op.drop_column("attributions", "explanation")
    op.drop_column("attributions", "dwell_time_seconds")
    op.drop_column("attributions", "blast_radius")
    op.drop_column("attributions", "reached_assets")
    op.drop_column("attributions", "attack_path")
    op.drop_column("attributions", "entry_point")

    # ── Incidents ────────────────────────────────────────────────────────
    op.drop_index("ix_incidents_last_seen", "incidents")
    op.drop_index("ix_incidents_first_seen", "incidents")
    op.drop_column("incidents", "last_seen")
    op.drop_column("incidents", "first_seen")
    op.drop_column("incidents", "layers")
    op.drop_column("incidents", "risk_level")
    op.drop_column("incidents", "risk_score")

    # ── Alerts ───────────────────────────────────────────────────────────
    op.drop_index("ix_alerts_entity_id", "alerts")
    op.drop_index("ix_alerts_technique_id", "alerts")
    op.drop_index("ix_alerts_technique", "alerts")
    op.drop_index("ix_alerts_detector", "alerts")
    op.drop_column("alerts", "evidence")
    op.drop_column("alerts", "decision")
    op.drop_column("alerts", "confidence")
    op.drop_column("alerts", "score")
    op.drop_column("alerts", "entity_id")
    op.drop_column("alerts", "technique_id")
    op.drop_column("alerts", "technique")
    op.drop_column("alerts", "detector_version")
    op.drop_column("alerts", "detector")

    # ── Events ───────────────────────────────────────────────────────────
    op.drop_column("events", "metadata")
    op.drop_column("events", "entities")
