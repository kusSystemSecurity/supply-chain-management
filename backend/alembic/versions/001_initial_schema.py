"""initial schema

Revision ID: 001
Revises:
Create Date: 2025-01-10 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create scans table
    op.create_table(
        'scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scan_type', sa.String(length=50), nullable=False),
        sa.Column('target', sa.String(length=500), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=False),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('result_json', sa.JSON(), nullable=True),
        sa.Column('error_message', sa.String(length=1000), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scans_status'), 'scans', ['status'], unique=False)
    op.create_index(op.f('ix_scans_started_at'), 'scans', ['started_at'], unique=False)

    # Create vulnerabilities table
    op.create_table(
        'vulnerabilities',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('cve_id', sa.String(length=20), nullable=False),
        sa.Column('package_name', sa.String(length=200), nullable=True),
        sa.Column('package_version', sa.String(length=100), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('epss_score', sa.Float(), nullable=True),
        sa.Column('epss_predicted', sa.Boolean(), default=False, nullable=True),
        sa.Column('cve_details', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_vulnerabilities_cve_id'), 'vulnerabilities', ['cve_id'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_scan_id'), 'vulnerabilities', ['scan_id'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_severity'), 'vulnerabilities', ['severity'], unique=False)

    # Create ai_analyses table
    op.create_table(
        'ai_analyses',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('agent_type', sa.String(length=50), nullable=False),
        sa.Column('input_data', sa.JSON(), nullable=True),
        sa.Column('output_data', sa.JSON(), nullable=True),
        sa.Column('tokens_used', sa.Integer(), nullable=True),
        sa.Column('processing_time_ms', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ai_analyses_scan_id'), 'ai_analyses', ['scan_id'], unique=False)
    op.create_index(op.f('ix_ai_analyses_agent_type'), 'ai_analyses', ['agent_type'], unique=False)


def downgrade() -> None:
    # Drop tables in reverse order
    op.drop_index(op.f('ix_ai_analyses_agent_type'), table_name='ai_analyses')
    op.drop_index(op.f('ix_ai_analyses_scan_id'), table_name='ai_analyses')
    op.drop_table('ai_analyses')

    op.drop_index(op.f('ix_vulnerabilities_severity'), table_name='vulnerabilities')
    op.drop_index(op.f('ix_vulnerabilities_scan_id'), table_name='vulnerabilities')
    op.drop_index(op.f('ix_vulnerabilities_cve_id'), table_name='vulnerabilities')
    op.drop_table('vulnerabilities')

    op.drop_index(op.f('ix_scans_started_at'), table_name='scans')
    op.drop_index(op.f('ix_scans_status'), table_name='scans')
    op.drop_table('scans')
