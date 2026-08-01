# Passkeys And WebAuthn

Passkeys are credentials based on WebAuthn and FIDO standards.

They use public-key cryptography instead of a shared secret. The authenticator keeps a private key, and the server stores the matching public key.

In this project, Passkeys are planned as a first-class MFA method. They do not automatically replace TOTP. They become the preferred phishing-resistant method when the server policy and the user's current device/browser allow them.

## Short History

WebAuthn Level 1 became a W3C Recommendation in 2019. WebAuthn Level 2 became a W3C Recommendation on 8 April 2021.

The term "passkey" became widely used when the ecosystem started promoting synced, user-friendly FIDO credentials for consumer authentication. FIDO's multi-device credential work made Passkeys practical across device ecosystems instead of limiting them to a single hardware authenticator.

For this project:

- WebAuthn is the browser/API standard;
- FIDO2/CTAP are the broader authenticator ecosystem pieces;
- Passkey is the user-facing credential experience built on those standards.

## Mental Model

With TOTP, the server and authenticator app share the same secret.

With Passkeys, the server does not store a shared secret. It stores a public key.

```text
TOTP

Authenticator app            Server
-----------------            -----------------
stores shared secret   <->   stores protected shared secret
generates code               recomputes expected code
```

```text
Passkey

Authenticator                Server
-------------                -----------------
stores private key     --->  stores public key
signs challenge              verifies signature
```

The private key should not leave the authenticator. The server verifies proof of possession without receiving the private key.

## Registration Flow

Registration creates a new credential for the user.

```text
Browser                    Server                    Authenticator
-------                    ------                    -------------
request setup
                           create challenge
<-------------------------- challenge/options
navigator.credentials.create()
                                                     create key pair
                                                     protect private key
                                                     return public key + attestation
send credential response
-------------------------> verify challenge/origin/RP/user
                           store credential id + public key
```

Important server checks:

- challenge matches a server-issued, unexpired challenge;
- origin is allowed;
- relying party id is correct;
- user identity is correct;
- user presence is satisfied;
- user verification policy is satisfied when required;
- credential id is stored for the right user;
- public key material is parsed and stored safely.

## Authentication Flow

Authentication proves possession of an existing credential.

```text
Browser                    Server                    Authenticator
-------                    ------                    -------------
request passkey login
                           create challenge
<-------------------------- challenge/options
navigator.credentials.get()
                                                     user unlocks authenticator
                                                     signs challenge
send assertion
-------------------------> verify challenge/origin/RP/signature
                           update last used metadata
                           complete MFA step
```

Important server checks:

- challenge matches a server-issued, unexpired challenge;
- origin is allowed;
- relying party id is correct;
- credential id belongs to the expected user;
- signature verifies against the stored public key;
- user presence is satisfied;
- user verification policy is satisfied when required;
- signature counter is evaluated when the authenticator provides one.

## Trousseau / Password Manager Model

Many users experience Passkeys through a platform keychain or password manager.

Examples:

- iCloud Keychain;
- Google Password Manager;
- Windows Hello;
- 1Password;
- Bitwarden;
- hardware security keys.

Simple model:

```text
User account on website
        |
        | registers a Passkey
        v
Credential provider / keychain
        |
        | protects private key with local unlock
        v
Biometric, device PIN, password manager unlock, or security key touch
```

The website does not receive the biometric or device PIN. The local authenticator uses that unlock to authorize access to the private key.

## Platform vs Roaming Authenticators

Platform authenticators are built into the device or OS.

Examples:

- Touch ID on macOS;
- Face ID on iOS;
- Windows Hello;
- Android device lock.

Roaming authenticators are external or portable.

Examples:

- hardware security key;
- phone used from a desktop through cross-device authentication.

Project implication:

- the server should store credentials individually;
- each credential can have a name;
- each credential can track last use;
- each credential can be revoked individually.

## Synced vs Device-Bound Credentials

Some Passkeys are synced by a provider across the user's devices.

Some credentials are device-bound and do not sync.

This matters for recovery:

```text
synced passkey       -> may survive phone/laptop replacement
device-bound passkey -> may be lost with the device
```

The server should not assume all Passkeys behave the same. It should store metadata that helps users understand and manage their credentials, while avoiding invasive fingerprinting.

## Cross-Device Authentication

Cross-device authentication lets a user authenticate on one device by using a Passkey available on another device.

Example:

```text
Desktop browser shows Passkey prompt / QR
        |
        v
User scans with phone
        |
        v
Phone holds or accesses the Passkey
        |
        v
Phone signs the server challenge
        |
        v
Desktop session completes authentication
```

Project implication:

- the login flow should not assume the Passkey is physically stored on the desktop;
- browser capability and transport availability affect the user experience;
- the server still validates the final WebAuthn assertion.

## Browser And Device Constraints

Passkey availability depends on the current environment.

A user may have a Passkey registered, but the current login attempt may still need another option because:

- the browser does not support the needed WebAuthn features;
- the site is not running in a secure context;
- the user is inside an embedded webview;
- platform policy disables Passkeys;
- the authenticator is unavailable;
- Bluetooth or cross-device transport is unavailable;
- the user is on a shared or locked-down machine;
- the user has no local unlock method configured.

Frontend capability detection can improve UX, but it is not an authorization decision.

The server remains responsible for:

- deciding which methods are allowed;
- validating every challenge response;
- deciding whether fallback is permitted;
- recording security events.

## Multi-Method MFA Strategy

The project should not treat Passkeys as a forced replacement for TOTP.

Target roles:

```text
Passkey         = preferred phishing-resistant MFA method when available
TOTP            = compatible multi-platform MFA method and controlled fallback
Recovery codes  = exceptional recovery method
Trusted device  = controlled friction reduction
```

The future method selection flow should look like this:

```text
password verified
        |
        v
server loads active MFA methods
        |
        v
server applies policy + risk checks
        |
        v
browser reports Passkey capability for UX
        |
        v
user chooses from allowed compatible methods
        |
        v
server verifies selected method
```

The user can choose only among methods that are both:

- allowed by server policy;
- technically usable in the current browser/device context.

## Security Strengths

Passkeys improve on passwords and TOTP in several important ways:

- the private key is not sent to the server;
- credentials are scoped to the relying party;
- phishing resistance is stronger than TOTP because a fake origin cannot use the real site's credential;
- there is no six-digit code for a user to type into a phishing site;
- credentials can be managed individually.

## Remaining Risks And Tradeoffs

Passkeys do not remove every auth problem.

Important tradeoffs:

- account recovery remains hard;
- users may lose access to a device-bound credential;
- synced credential ecosystems create provider dependency;
- some environments cannot use Passkeys reliably;
- cross-device flows may add UX confusion;
- server implementation must validate WebAuthn responses correctly;
- fallback methods can weaken Passkey security if they are easier to attack.

## Project Scope

`v0.8.0` should introduce WebAuthn registration and authentication primitives.

It should not immediately replace TOTP.

Expected focus:

- challenge generation;
- credential storage model;
- origin and RP ID validation;
- user presence and user verification policy;
- signature verification;
- signature counter handling when available;
- backend tests;
- focused frontend WebAuthn modules.

`v0.9.0` should connect these primitives to the Password + Passkey flow.

Later milestones should decide global MFA policy across Passkeys, TOTP, recovery codes, and trusted devices.

## Sources

- W3C WebAuthn Level 2 Recommendation: https://www.w3.org/TR/webauthn-2/
- W3C WebAuthn Level 3 Candidate Recommendation: https://www.w3.org/TR/webauthn-3/
- W3C WebAuthn Level 2 announcement: https://www.w3.org/blog/2021/04/webauthn-level-2-is-a-w3c-recommendation/
- FIDO Alliance Passkeys: https://fidoalliance.org/passkeys/
- FIDO Alliance Multi-Device FIDO Credentials white paper: https://fidoalliance.org/white-paper-multi-device-fido-credentials/
- MDN Web Authentication API: https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API
