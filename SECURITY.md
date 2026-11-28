# Security Policy

## Scope

This repository contains the Rust application-client layer for Majik Signature. It composes the `majik-signature` core crate with Majik Key account management, contact/group handling, storage, history, backups, and native-path streaming adapters.

The client crate is not a substitute for a security review of the core cryptographic implementation, operating system, storage backend, Tauri host, or application deployment. A reported issue may affect this repository, a dependency, or an integration boundary.

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities in a public issue, pull request, discussion, or commit.

Use GitHub private vulnerability reporting for this repository when available (open the repository's **Security** tab and select **Report a vulnerability**). Include the affected version or commit, operating system/toolchain, impact, and a minimal reproduction where practical. Redact personal data and operational secrets.

Never include private keys, mnemonic/recovery phrases, authentication tokens, unredacted user documents, production database files, or production credentials in a report.

If private vulnerability reporting is unavailable, contact the repository maintainers through GitHub and request a private reporting channel before sending technical details.

## Security assumptions and safe use

- Treat files, detached envelopes, MJKSMAP manifests, contact cards, backups, and metadata received from outside the application as untrusted input.
- Use a public key/contact established through an independently trusted channel for identity-sensitive verification. A valid signature does not independently establish the real-world identity or authorization of the key owner.
- Select storage adapters appropriate to the host application's threat model. Do not assume the default in-memory adapter provides persistence or encrypted-at-rest storage.
- Keep private keys and recovery phrases secret. Avoid writing key material or source-file contents to logs, crash reports, temporary artifacts, or support bundles.
- Streaming avoids materializing large source files in memory but does not make arbitrary files safe to render, extract, or execute. Apply application-level file-type, size, and workflow authorization rules.
- Use maintained versions of this crate and its dependencies. This project does not claim an independent third-party cryptographic audit or certification.

## Supported versions

Reports are assessed against the latest maintained release or development branch. This project does not currently publish a guaranteed security-support window for older versions; upgrading to the latest maintained version is recommended.

## Coordinated disclosure

Please allow maintainers a reasonable opportunity to investigate, prepare a fix, and coordinate an update before public disclosure. Reporter identity and submitted sensitive material will not be published without permission.
