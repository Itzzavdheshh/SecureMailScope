"""Initial schema — Core domain models

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-09-27 04:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ─── 1. Captures ─────────────────────────────────────────────────────────
    op.create_table(
        'captures',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('filename', sa.String(length=255), nullable=False),
        sa.Column('file_path', sa.String(length=1024), nullable=False),
        sa.Column('file_size_bytes', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('total_packets', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('capture_start_time', sa.DateTime(timezone=True), nullable=True),
        sa.Column('capture_end_time', sa.DateTime(timezone=True), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='UPLOADED'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_captures_filename'), 'captures', ['filename'], unique=False)
    op.create_index(op.f('ix_captures_sha256_hash'), 'captures', ['sha256_hash'], unique=False)

    # ─── 2. Analysis Jobs ────────────────────────────────────────────────────
    op.create_table(
        'analysis_jobs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('capture_id', sa.String(length=36), nullable=False),
        sa.Column('status', sa.Enum('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', name='jobstatus'), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('options_json', sa.Text(), nullable=True),
        sa.Column('total_sessions', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_findings', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('overall_risk_score', sa.Float(), nullable=True),
        sa.Column('risk_band', sa.Enum('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SECURE', name='riskband'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['capture_id'], ['captures.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_analysis_jobs_capture_id'), 'analysis_jobs', ['capture_id'], unique=False)
    op.create_index(op.f('ix_analysis_jobs_status'), 'analysis_jobs', ['status'], unique=False)

    # ─── 3. Infrastructure Identities ────────────────────────────────────────
    op.create_table(
        'infrastructure_identities',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('organization', sa.String(length=255), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('current_risk_score', sa.Float(), nullable=True),
        sa.Column('current_risk_band', sa.Enum('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SECURE', name='riskband_infra'), nullable=True),
        sa.Column('last_evaluated_job_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['last_evaluated_job_id'], ['analysis_jobs.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('ip_address')
    )
    op.create_index(op.f('ix_infrastructure_identities_hostname'), 'infrastructure_identities', ['hostname'], unique=False)
    op.create_index(op.f('ix_infrastructure_identities_ip_address'), 'infrastructure_identities', ['ip_address'], unique=True)

    # ─── 4. Drift Events ─────────────────────────────────────────────────────
    op.create_table(
        'drift_events',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('infrastructure_id', sa.String(length=36), nullable=False),
        sa.Column('capture_id', sa.String(length=36), nullable=True),
        sa.Column('job_id', sa.String(length=36), nullable=True),
        sa.Column('event_type', sa.Enum('CIPHER_DOWNGRADE', 'TLS_VERSION_DOWNGRADE', 'CERT_EXPIRED', 'CERT_CHANGED', 'STARTTLS_DISABLED', 'RISK_SCORE_INCREASED', name='drifteventtype'), nullable=False),
        sa.Column('previous_state', sa.Text(), nullable=True),
        sa.Column('new_state', sa.Text(), nullable=True),
        sa.Column('delta_description', sa.Text(), nullable=False),
        sa.Column('risk_delta', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['capture_id'], ['captures.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['infrastructure_id'], ['infrastructure_identities.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['job_id'], ['analysis_jobs.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_drift_events_infrastructure_id'), 'drift_events', ['infrastructure_id'], unique=False)

    # ─── 5. Email Sessions ───────────────────────────────────────────────────
    op.create_table(
        'email_sessions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('job_id', sa.String(length=36), nullable=False),
        sa.Column('session_index', sa.Integer(), nullable=False),
        sa.Column('client_ip', sa.String(length=45), nullable=False),
        sa.Column('client_port', sa.Integer(), nullable=False),
        sa.Column('server_ip', sa.String(length=45), nullable=False),
        sa.Column('server_port', sa.Integer(), nullable=False),
        sa.Column('protocol', sa.Enum('SMTP', 'IMAP', 'POP3', 'UNKNOWN', name='protocoltype'), nullable=False),
        sa.Column('is_tls_implicit', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('starttls_state', sa.Enum('NOT_OBSERVED', 'ADVERTISED', 'ATTEMPTED', 'ACCEPTED', 'REJECTED', 'ANOMALOUS', name='starttlsstatus'), nullable=False),
        sa.Column('start_time', sa.DateTime(timezone=True), nullable=True),
        sa.Column('end_time', sa.DateTime(timezone=True), nullable=True),
        sa.Column('packet_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('bytes_transferred', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('banner', sa.Text(), nullable=True),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.ForeignKeyConstraint(['job_id'], ['analysis_jobs.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_email_sessions_client_ip'), 'email_sessions', ['client_ip'], unique=False)
    op.create_index(op.f('ix_email_sessions_job_id'), 'email_sessions', ['job_id'], unique=False)
    op.create_index(op.f('ix_email_sessions_protocol'), 'email_sessions', ['protocol'], unique=False)
    op.create_index(op.f('ix_email_sessions_server_ip'), 'email_sessions', ['server_ip'], unique=False)
    op.create_index(op.f('ix_email_sessions_session_index'), 'email_sessions', ['session_index'], unique=False)
    op.create_index(op.f('ix_email_sessions_starttls_state'), 'email_sessions', ['starttls_state'], unique=False)

    # ─── 6. Starttls States ──────────────────────────────────────────────────
    op.create_table(
        'starttls_states',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('session_id', sa.String(length=36), nullable=False),
        sa.Column('observed_state', sa.Enum('NOT_OBSERVED', 'ADVERTISED', 'ATTEMPTED', 'ACCEPTED', 'REJECTED', 'ANOMALOUS', name='starttlsstatus_state'), nullable=False),
        sa.Column('advertised_in_frame', sa.Integer(), nullable=True),
        sa.Column('command_in_frame', sa.Integer(), nullable=True),
        sa.Column('response_in_frame', sa.Integer(), nullable=True),
        sa.Column('response_code', sa.Integer(), nullable=True),
        sa.Column('is_downgrade_detected', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('state_details_json', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['session_id'], ['email_sessions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('session_id')
    )
    op.create_index(op.f('ix_starttls_states_session_id'), 'starttls_states', ['session_id'], unique=True)

    # ─── 7. Tls Handshakes ───────────────────────────────────────────────────
    op.create_table(
        'tls_handshakes',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('session_id', sa.String(length=36), nullable=False),
        sa.Column('client_hello_frame', sa.Integer(), nullable=True),
        sa.Column('server_hello_frame', sa.Integer(), nullable=True),
        sa.Column('offered_tls_versions', sa.Text(), nullable=True),
        sa.Column('negotiated_tls_version', sa.String(length=32), nullable=True),
        sa.Column('client_cipher_suites', sa.Text(), nullable=True),
        sa.Column('negotiated_cipher_suite', sa.String(length=128), nullable=True),
        sa.Column('key_exchange_group', sa.String(length=64), nullable=True),
        sa.Column('key_exchange_bits', sa.Integer(), nullable=True),
        sa.Column('is_forward_secrecy', sa.Boolean(), nullable=True),
        sa.Column('sni_hostname', sa.String(length=255), nullable=True),
        sa.Column('alpn_protocols', sa.Text(), nullable=True),
        sa.Column('handshake_status', sa.String(length=32), nullable=False, server_default='ATTEMPTED'),
        sa.Column('raw_client_hello_bytes', sa.LargeBinary(), nullable=True),
        sa.Column('raw_server_hello_bytes', sa.LargeBinary(), nullable=True),
        sa.ForeignKeyConstraint(['session_id'], ['email_sessions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('session_id')
    )
    op.create_index(op.f('ix_tls_handshakes_session_id'), 'tls_handshakes', ['session_id'], unique=True)

    # ─── 8. Certificates ─────────────────────────────────────────────────────
    op.create_table(
        'certificates',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('session_id', sa.String(length=36), nullable=False),
        sa.Column('certificate_index', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('is_server_cert', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('subject_dn', sa.Text(), nullable=True),
        sa.Column('issuer_dn', sa.Text(), nullable=True),
        sa.Column('serial_number', sa.String(length=128), nullable=True),
        sa.Column('not_before', sa.DateTime(timezone=True), nullable=True),
        sa.Column('not_after', sa.DateTime(timezone=True), nullable=True),
        sa.Column('public_key_type', sa.String(length=32), nullable=True),
        sa.Column('public_key_size_bits', sa.Integer(), nullable=True),
        sa.Column('signature_algorithm', sa.String(length=64), nullable=True),
        sa.Column('is_weak_signature', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('sha256_fingerprint', sa.String(length=64), nullable=True),
        sa.Column('sha1_fingerprint', sa.String(length=40), nullable=True),
        sa.Column('is_self_signed', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('is_valid_at_capture', sa.Boolean(), nullable=True),
        sa.Column('san_domains', sa.Text(), nullable=True),
        sa.Column('raw_der_bytes', sa.LargeBinary(), nullable=True),
        sa.ForeignKeyConstraint(['session_id'], ['email_sessions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_certificates_session_id'), 'certificates', ['session_id'], unique=False)
    op.create_index(op.f('ix_certificates_sha256_fingerprint'), 'certificates', ['sha256_fingerprint'], unique=False)

    # ─── 9. Certificate Chains ───────────────────────────────────────────────
    op.create_table(
        'certificate_chains',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('session_id', sa.String(length=36), nullable=False),
        sa.Column('chain_length', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('is_chain_complete', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('validation_status', sa.String(length=64), nullable=False, server_default='UNCHECKED'),
        sa.Column('validation_notes', sa.Text(), nullable=True),
        sa.Column('root_issuer_dn', sa.Text(), nullable=True),
        sa.Column('leaf_subject_dn', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['session_id'], ['email_sessions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('session_id')
    )
    op.create_index(op.f('ix_certificate_chains_session_id'), 'certificate_chains', ['session_id'], unique=True)

    # ─── 10. Findings ────────────────────────────────────────────────────────
    op.create_table(
        'findings',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('job_id', sa.String(length=36), nullable=False),
        sa.Column('session_id', sa.String(length=36), nullable=True),
        sa.Column('rule_id', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('category', sa.Enum('TLS_CRYPTO', 'X509_CERT', 'STARTTLS', 'PROTOCOL_ANOMALY', name='findingcategory'), nullable=False),
        sa.Column('severity', sa.Enum('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', name='severity'), nullable=False),
        sa.Column('confidence', sa.Enum('HIGH', 'MEDIUM', 'LOW', name='confidence'), nullable=False),
        sa.Column('status', sa.Enum('OBSERVED', 'ANALYZED', 'INFERRED', 'INSUFFICIENT_EVIDENCE', name='evidencestatus'), nullable=False),
        sa.Column('score_contribution', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('remediation_recommendation', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['job_id'], ['analysis_jobs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['session_id'], ['email_sessions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_findings_job_id'), 'findings', ['job_id'], unique=False)
    op.create_index(op.f('ix_findings_rule_id'), 'findings', ['rule_id'], unique=False)
    op.create_index(op.f('ix_findings_session_id'), 'findings', ['session_id'], unique=False)
    op.create_index(op.f('ix_findings_severity'), 'findings', ['severity'], unique=False)

    # ─── 11. Evidence Records ────────────────────────────────────────────────
    op.create_table(
        'evidence_records',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('finding_id', sa.String(length=36), nullable=False),
        sa.Column('capture_id', sa.String(length=36), nullable=False),
        sa.Column('session_id', sa.String(length=36), nullable=True),
        sa.Column('frame_number', sa.Integer(), nullable=False),
        sa.Column('packet_timestamp', sa.Float(), nullable=False),
        sa.Column('protocol_layer', sa.String(length=32), nullable=False),
        sa.Column('field_name', sa.String(length=128), nullable=False),
        sa.Column('observed_value', sa.Text(), nullable=False),
        sa.Column('source_reference', sa.String(length=255), nullable=True),
        sa.Column('evidence_status', sa.Enum('OBSERVED', 'ANALYZED', 'INFERRED', 'INSUFFICIENT_EVIDENCE', name='evidencestatus_ev'), nullable=False),
        sa.Column('hex_dump_snippet', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['capture_id'], ['captures.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['session_id'], ['email_sessions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_evidence_records_capture_id'), 'evidence_records', ['capture_id'], unique=False)
    op.create_index(op.f('ix_evidence_records_finding_id'), 'evidence_records', ['finding_id'], unique=False)
    op.create_index(op.f('ix_evidence_records_frame_number'), 'evidence_records', ['frame_number'], unique=False)
    op.create_index(op.f('ix_evidence_records_packet_timestamp'), 'evidence_records', ['packet_timestamp'], unique=False)
    op.create_index(op.f('ix_evidence_records_session_id'), 'evidence_records', ['session_id'], unique=False)

    # ─── 12. Timeline Events ─────────────────────────────────────────────────
    op.create_table(
        'timeline_events',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('job_id', sa.String(length=36), nullable=False),
        sa.Column('session_id', sa.String(length=36), nullable=True),
        sa.Column('timestamp', sa.Float(), nullable=False),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('frame_number', sa.Integer(), nullable=True),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('detail_json', sa.Text(), nullable=True),
        sa.Column('severity', sa.Enum('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', name='severity_tl'), nullable=False),
        sa.ForeignKeyConstraint(['job_id'], ['analysis_jobs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['session_id'], ['email_sessions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_timeline_events_event_type'), 'timeline_events', ['event_type'], unique=False)
    op.create_index(op.f('ix_timeline_events_job_id'), 'timeline_events', ['job_id'], unique=False)
    op.create_index(op.f('ix_timeline_events_session_id'), 'timeline_events', ['session_id'], unique=False)
    op.create_index(op.f('ix_timeline_events_timestamp'), 'timeline_events', ['timestamp'], unique=False)


def downgrade() -> None:
    op.drop_table('timeline_events')
    op.drop_table('evidence_records')
    op.drop_table('findings')
    op.drop_table('certificate_chains')
    op.drop_table('certificates')
    op.drop_table('tls_handshakes')
    op.drop_table('starttls_states')
    op.drop_table('email_sessions')
    op.drop_table('drift_events')
    op.drop_table('infrastructure_identities')
    op.drop_table('analysis_jobs')
    op.drop_table('captures')
