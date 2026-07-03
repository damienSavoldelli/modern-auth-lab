# Passkeys And WebAuthn

Passkeys are based on public-key cryptography and WebAuthn.

Unlike TOTP, Passkeys can be represented as distinct credentials. This makes device and credential lifecycle management more precise.

## Core Idea

During registration:

- the server creates a challenge;
- the browser asks an authenticator to create a credential;
- the authenticator creates a key pair;
- the private key stays protected by the authenticator;
- the public key and credential metadata are stored by the server.

During authentication:

- the server creates a fresh challenge;
- the authenticator signs the challenge;
- the server verifies the signature with the stored public key.

## Security Implications

Passkeys help protect against phishing because credentials are scoped to the relying party and origin.

Implementation must still verify:

- challenge freshness;
- origin;
- relying party id;
- user presence;
- user verification policy;
- signature validity;
- signature counter behavior when available.

## Lifecycle Difference With TOTP

TOTP usually means one shared secret that may be copied to multiple devices.

Passkeys can be modeled as multiple credentials:

- each credential can be named;
- each credential can record last use;
- each credential can be revoked individually;
- recovery flows can reason about credential inventory.

## Project Scope

Passkeys are not part of `v0.5.0`. This note exists to keep the TOTP design honest about what TOTP cannot do well, especially per-device revocation.
