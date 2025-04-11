# JSON-Web-Token
A **JSON Web Token (JWT)** is a compact, self-contained way to represent information between two parties, typically used for authentication and authorization in web applications. It’s encoded as a JSON object and digitally signed to ensure its integrity, making it secure for transmitting data like user identity or permissions.

### Structure of a JWT
A JWT consists of three main parts, separated by dots (`.`):
1. **Header**: Contains metadata about the token, like the signing algorithm (e.g., HMAC SHA256 or RSA). Example:
   ```json
   {
     "alg": "HS256",
     "typ": "JWT"
   }
   ```
   This is Base64Url-encoded.

2. **Payload**: Contains the claims, which are statements about an entity (e.g., user) and additional data. Claims can be:
   - **Registered claims**: Standard fields like `iss` (issuer), `sub` (subject), `exp` (expiration time), etc.
   - **Public claims**: Custom fields defined by the application.
   - **Private claims**: Custom fields shared between specific parties.
   Example:
   ```json
   {
     "sub": "user123",
     "name": "John Doe",
     "iat": 1697051234
   }
   ```
   This is also Base64Url-encoded.

3. **Signature**: Ensures the token’s authenticity. It’s created by taking the encoded header, encoded payload, a secret key (or private key for asymmetric algorithms), and signing them using the algorithm specified in the header. For example, with HMAC SHA256:
   ```
   HMACSHA256(
     base64UrlEncode(header) + "." + base64UrlEncode(payload),
     secret
   )
   ```

The final JWT looks like this:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNjk3MDUxMjM0fQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### How JWT Works
1. **Authentication**: When a user logs in, the server verifies credentials and generates a JWT containing user details (e.g., user ID, roles).
2. **Transmission**: The client (e.g., browser or app) sends the JWT in the HTTP `Authorization` header (as `Bearer <token>`) or in cookies with each request.
3. **Verification**: The server validates the JWT’s signature using the secret or public key. If valid, it trusts the payload’s claims to authorize access.
4. **Statelessness**: JWTs are self-contained, so the server doesn’t need to store session data—it just verifies the token.

### Common Use Cases
- **Authentication**: Verify user identity across requests in APIs or single-page applications.
- **Authorization**: Encode user roles or permissions to control access to resources.
- **Secure Data Exchange**: Share trusted data between services (e.g., microservices or third-party integrations).

### Advantages
- **Compact**: Easy to transmit in headers or URLs.
- **Stateless**: No server-side session storage needed.
- **Cross-domain**: Works across different domains, ideal for APIs and microservices.
- **Flexible**: Payload can include custom claims for various purposes.

### Disadvantages
- **Non-revocable**: Once issued, a JWT is valid until it expires unless a revocation mechanism (e.g., blacklist) is implemented.
- **Size**: Can be larger than traditional session IDs, impacting bandwidth.
- **Security Risks**: If not properly secured (e.g., weak signing keys or misconfigured algorithms), JWTs can be vulnerable to attacks like token tampering or replay attacks.
- **Sensitive Data**: Payload is only Base64-encoded, not encrypted, so avoid storing sensitive data unless encrypted separately.

### Security Best Practices
- Use strong signing keys and secure algorithms (e.g., HS256, RS256; avoid `none`).
- Set reasonable expiration times (`exp`) to limit token lifespan.
- Use HTTPS to prevent interception.
- Avoid storing sensitive data in the payload unless encrypted.
- Implement token refresh mechanisms for long-lived sessions.
- Validate all claims (e.g., `iss`, `aud`) on the server.

JWTs are widely used in modern web development, especially with frameworks like OAuth 2.0 and OpenID Connect, balancing simplicity with security when implemented correctly. If you’d like a deeper dive into any aspect (e.g., implementation, attacks, or specific use cases), let me know!
