# Passkeys And WebAuthn

Passkeys are planned as a first-class authentication factor in v1.0.

## Goals

- Support multiple Passkeys per user.
- Allow users to name Passkeys.
- Track last use.
- Revoke individual Passkeys.
- Support platform authenticators and cross-device authentication.
- Keep lifecycle events auditable.

## WebAuthn Verification Requirements

Server-side verification must validate:

- Challenge.
- Origin.
- RP ID.
- User presence.
- User verification policy.
- Credential ID ownership.
- Signature.
- Signature counter when available.

## Lifecycle Events

The Passkey lifecycle includes:

- Registration challenge created.
- Credential registered.
- Credential renamed.
- Credential used.
- Last-used timestamp updated.
- Credential revoked.
- Lost-device or recovery path triggered.

Each security-sensitive lifecycle event should be represented in security logs.

## Educational Constraints

The project should use a mature WebAuthn implementation when the time comes. It should still explain the protocol checks instead of hiding them behind a black box.
