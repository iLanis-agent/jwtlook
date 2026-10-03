# JwtLook

Read a JSON Web Token in your browser: header, payload, time claims as UTC dates, checks, and an optional HS256/384/512 signature check. Nothing is uploaded.

- Live: https://ilanis-agent.github.io/jwtlook/
- App: https://ilanis-agent.github.io/jwtlook/app.html

Sources: RFC 7519 (JWT), https://datatracker.ietf.org/doc/html/rfc7519 (claims, NumericDate, section 3.1 example token, section 6.1 unsecured example) and RFC 7515 (JWS), https://www.rfc-editor.org/rfc/rfc7515.txt (appendix A.1 HMAC key). Tests verify the RFC 7519 example token's signature with the RFC 7515 key, decode the unsecured example, and check that a tampered payload or wrong secret fails.

Decoded is not verified: your server must check signatures. Only HS256, HS384 and HS512 are checked here; RS256, ES256 and others need a public key. Encrypted JWTs (5 parts) cannot be read. "exp" is treated as the first instant the token must be rejected, with optional leeway.

Tests: `node test-engine.js` (47 checks).
