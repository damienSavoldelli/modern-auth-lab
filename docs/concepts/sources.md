# Security Sources

This page lists stable references used to guide security-sensitive documentation and implementation decisions.

Prefer primary standards and established security references before blog posts or tutorials.

## OTP And TOTP

- RFC 6238, TOTP: Time-Based One-Time Password Algorithm  
  https://datatracker.ietf.org/doc/html/rfc6238

- RFC 4226, HOTP: An HMAC-Based One-Time Password Algorithm  
  https://datatracker.ietf.org/doc/html/rfc4226

- Google Authenticator Key URI Format  
  https://github.com/google/google-authenticator/wiki/Key-Uri-Format

- Yubico OATH URI String Format  
  https://docs.yubico.com/yesdk/users-manual/application-oath/uri-string-format.html

- Libsodium secret-key authenticated encryption  
  https://doc.libsodium.org/secret-key_cryptography/secretbox

- chillerlan/php-qrcode  
  https://github.com/chillerlan/php-qrcode

## WebAuthn And Passkeys

- W3C WebAuthn Level 3 specification  
  https://www.w3.org/TR/webauthn-3/

- W3C WebAuthn Level 2 Recommendation, 8 April 2021
  https://www.w3.org/TR/webauthn-2/

- W3C announcement for WebAuthn Level 2 Recommendation
  https://www.w3.org/blog/2021/04/webauthn-level-2-is-a-w3c-recommendation/

- FIDO Alliance Passkeys
  https://fidoalliance.org/passkeys/

- FIDO Alliance white paper: Multi-Device FIDO Credentials
  https://fidoalliance.org/white-paper-multi-device-fido-credentials/

- MDN Web Authentication API
  https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API

## MFA And Authentication Security

- OWASP Multifactor Authentication Cheat Sheet  
  https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html

- OWASP Testing Multi-Factor Authentication  
  https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/11-Testing_Multi-Factor_Authentication

- OWASP Authentication Cheat Sheet  
  https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

- OWASP Top 10 2021, Identification and Authentication Failures  
  https://owasp.org/Top10/2021/A07_2021-Identification_and_Authentication_Failures/
