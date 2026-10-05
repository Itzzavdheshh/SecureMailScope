# Cryptographic Security Fingerprint v1

The fingerprint is a derived view over a persisted `EmailSession`, `TlsHandshake`,
certificate/chain, STARTTLS state, findings, and its `AnalysisJob`. It does not add
database columns or infer fields that the current PCAP parser did not observe.

## Shape

`GET /api/v1/sessions/{session_id}/fingerprint` returns:

- `fingerprint_version`: schema version (`1.0.0`).
- `identity`: protocol, server endpoint, observed hostname, and a matching
  infrastructure identity only when that identity was evaluated by this job.
- `stable_profile`: observed STARTTLS/TLS properties, offered values, JA3/JA3S,
  and the server certificate and chain properties.
- `security_posture`: analysis-job risk/band, session risk, and finding summary.
- `evidence`: capture/job/session IDs, observation time, and persisted handshake,
  STARTTLS, and finding frame references.
- `fingerprint_hash`: SHA-256 of the canonical stable profile.

Missing properties are `null`; they are not replaced with a secure/default value.
The standard JA3 and JA3S MD5 fingerprints are protocol fingerprint values, not
security hashes. They are reparsed from stored ClientHello/ServerHello handshake
bytes. If those bytes were not persisted, the corresponding value remains null.

## Hash Contract

The hash input is UTF-8 JSON serialized with sorted keys, compact separators, and
ASCII escaping. SHA-256 is applied to the recursively normalized stable profile,
omitting null-valued properties. It includes protocol, implicit-TLS flag, STARTTLS
state, TLS version, negotiated cipher, key-exchange group, forward-secrecy flag,
offered TLS versions/ciphers, JA3/JA3S hashes, and observed certificate/chain
properties (fingerprint, subject, issuer, SANs, key type/size, signature algorithm,
validity at capture, self-signed flag, chain status).

It excludes endpoint identity (IP, port, hostname, infrastructure ID), session and
job/capture IDs, timestamps, packet/frame references, findings, risk values, and
severity counts. Risk is deliberately not a cryptographic property and remains a
separate, job-scoped persisted result. A newly observed property can therefore
change the hash without proving that the underlying service changed.

## Comparison

`GET /api/v1/sessions/{session_id}/fingerprint/compare/{other_session_id}` compares
stable-profile leaf fields. It reports `CHANGED` with field-level before/after
values only when both observations exist and differ. `UNCHANGED` means the hashes
match. `INDETERMINATE` means hashes differ but there is no field observed on both
sides that proves a posture change; missing evidence is listed separately.

## Evidence Boundary

ClientHello and ServerHello frame numbers come from `TlsHandshake`; STARTTLS frame
numbers come from the persisted state machine; finding frames come from linked
evidence records. The current certificate model stores parsed certificate facts
and DER bytes but not the original Certificate-message frame number. Consequently
the fingerprint reports `frames.certificate: null`; it does not reuse a nearby
ServerHello or finding frame as if it were the certificate frame. TLS 1.3
certificates unavailable in the capture remain not observed.

The session API and JSON/HTML/PDF reports expose the same derived version/hash.
No longitudinal fleet clustering or automated posture-evolution scoring is
implemented in this foundation.
