# 0020 - WebAuthn Library Boundary

## Status

Accepted

## Context

WebAuthn verification is security-sensitive.

The server must eventually validate:

- challenge;
- origin;
- RP ID hash;
- client data;
- authenticator data;
- attestation response;
- assertion response;
- user presence;
- user verification;
- public-key signature;
- signature counter behavior when available.

Implementing that parsing and cryptographic verification manually would create unnecessary risk and would distract from the educational goal of understanding the authentication flow.

The project is intentionally vanilla PHP, but "vanilla" does not mean hand-rolling complex security protocols.

## Decision

The project will use `web-auth/webauthn-lib` as the backend WebAuthn verification dependency.

The dependency must be isolated behind project-owned classes under `src/Security/WebAuthn/` and `src/Application/WebAuthn/`.

Controllers must not become tightly coupled to the library API.

The project will use local DTOs or response objects at the application boundary where that keeps the code easier to understand and test.

## Consequences

The project adds a runtime dependency and its transitive dependencies for CBOR, COSE, serialization, and cryptographic WebAuthn verification.

This increases dependency weight, but provides clear security value:

- protocol parsing is delegated to a maintained WebAuthn library;
- cryptographic verification is not reimplemented locally;
- future WebAuthn behavior can follow a real standards-aware API;
- the project remains free to replace or wrap the library if needed because controllers should depend on local services.

The implementation must still define its own security policy:

- allowed origins;
- RP ID;
- challenge lifetime;
- user verification requirement;
- accepted attestation posture;
- security event behavior;
- fallback behavior.

## Rejected Alternatives

Hand-rolled WebAuthn verification was rejected because WebAuthn uses binary formats, client data validation, authenticator data validation, COSE keys, CBOR parsing, signature checks, and subtle ceremony rules.

Using a framework-specific Symfony bundle was rejected because the project is intentionally vanilla PHP at this stage.

Deferring the library choice until after persistence was rejected because the credential storage model depends on the verified credential data returned by the WebAuthn verification boundary.
