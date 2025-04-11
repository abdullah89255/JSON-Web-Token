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
Below are detailed examples of JSON Web Tokens (JWTs) in different scenarios, showing how they’re created, used, and verified. Each example includes the context, token structure, and practical details to illustrate JWTs in action.

---

### Example 1: User Authentication in a REST API
**Scenario**: A user logs into a web application (e.g., a Node.js backend with a React frontend) via email and password. The server issues a JWT to authenticate subsequent requests.

**Details**:
- **Tech Stack**: Node.js server with `jsonwebtoken` library, React client.
- **Algorithm**: HMAC SHA256 (HS256) with a secret key.
- **Flow**:
  1. User submits `email: "alice@example.com"` and `password: "secure123"`.
  2. Server verifies credentials against a database.
  3. If valid, server generates a JWT.
  4. Client stores the JWT (e.g., in `localStorage`) and includes it in future requests.

**JWT Creation** (Node.js):
```javascript
const jwt = require('jsonwebtoken');
const secret = 'my-secure-secret-key'; // Should be stored in env variables

const user = {
  id: 'user123',
  email: 'alice@example.com',
  role: 'admin'
};

const payload = {
  sub: user.id,
  email: user.email,
  role: user.role,
  iat: Math.floor(Date.now() / 1000), // Issued at (current timestamp)
  exp: Math.floor(Date.now() / 1000) + (60 * 60) // Expires in 1 hour
};

const token = jwt.sign(payload, secret, { algorithm: 'HS256' });
console.log(token);
```

**JWT Output**:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcyODkyMzQ1NiwiZXhwIjoxNzI4OTI3MDU2fQ.7z9zKxYpZ2Qv5vW3nX8mY0cD6bF7gH9iJ2kL3mN4oP8
```

**Decoded JWT**:
- **Header**:
  ```json
  {
    "alg": "HS256",
    "typ": "JWT"
  }
  ```
- **Payload**:
  ```json
  {
    "sub": "user123",
    "email": "alice@example.com",
    "role": "admin",
    "iat": 1728923456,
    "exp": 1728927056
  }
  ```
- **Signature**: Generated using the secret key.

**Client Usage**:
- The React app sends the JWT in the `Authorization` header for protected routes:
  ```javascript
  fetch('https://api.example.com/protected', {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  })
  .then(response => response.json())
  .then(data => console.log(data));
  ```

**Server Verification**:
```javascript
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Extract Bearer token
  if (!token) return res.status(401).send('No token provided');

  try {
    const decoded = jwt.verify(token, secret);
    req.user = decoded; // Attach payload to request
    next();
  } catch (error) {
    return res.status(403).send('Invalid token');
  }
};
```

**Outcome**: The server verifies the token’s signature and checks `exp`. If valid, it allows access to the protected resource, using `req.user.role` for authorization (e.g., only admins can access certain endpoints).

---

### Example 2: Role-Based Authorization in a Microservices Architecture
**Scenario**: A microservices-based e-commerce platform uses JWTs to control access to services (e.g., Order Service, User Service). The token includes user roles to enforce permissions.

**Details**:
- **Tech Stack**: Spring Boot (Java) services, JWT signed with RSA (asymmetric key pair).
- **Algorithm**: RS256 (RSA with SHA256).
- **Flow**:
  1. User logs in via an Authentication Service.
  2. Auth Service generates a JWT with role-based claims.
  3. Other services (e.g., Order Service) verify the JWT using the public key.

**JWT Creation** (Java with `jjwt` library):
```java
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;

public class JwtExample {
  public static void main(String[] args) throws Exception {
    // Generate RSA key pair
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair keyPair = keyGen.generateKeyPair();

    // Create payload
    String userId = "user456";
    String role = "customer";
    long now = System.currentTimeMillis();
    String jwt = Jwts.builder()
        .setSubject(userId)
        .claim("role", role)
        .setIssuedAt(new Date(now))
        .setExpiration(new Date(now + 3600_000)) // 1 hour
        .signWith(keyPair.getPrivate(), SignatureAlgorithm.RS256)
        .compact();

    System.out.println(jwt);
  }
}
```

**JWT Output** (example, shortened for brevity):
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyNDU2Iiwicm9sZSI6ImN1c3RvbWVyIiwiaWF0IjoxNzI4OTIzNDU2LCJleHAiOjE3Mjg5MjcwNTZ9.<signature>
```

**Verification in Order Service**:
- The Order Service receives the JWT and verifies it using the public key:
```java
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class OrderService {
  public void processOrder(String jwt, PublicKey publicKey) {
    try {
      Claims claims = Jwts.parserBuilder()
          .setSigningKey(publicKey)
          .build()
          .parseClaimsJws(jwt)
          .getBody();

      String role = claims.get("role", String.class);
      if (!"customer".equals(role)) {
        throw new SecurityException("Only customers can place orders");
      }
      System.out.println("Order processed for user: " + claims.getSubject());
    } catch (Exception e) {
      throw new SecurityException("Invalid JWT: " + e.getMessage());
    }
  }
}
```

**Outcome**: The Order Service trusts the JWT because it’s signed with the private key, verifiable by the public key. It checks the `role` claim to ensure only customers can place orders. RSA ensures security even if the public key is shared across services.

---

### Example 3: Single Sign-On (SSO) with OpenID Connect
**Scenario**: A company uses OpenID Connect (OIDC) for SSO across multiple apps (e.g., HR portal, expense tracker). A JWT serves as an ID token to share user identity.

**Details**:
- **Tech Stack**: Identity Provider (IdP) like Keycloak, apps using OIDC libraries.
- **Algorithm**: RS256.
- **Flow**:
  1. User logs into the IdP.
  2. IdP issues a JWT (ID token) with user details.
  3. Apps verify the token to grant access.

**JWT Example** (Issued by Keycloak):
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJ4YzEifQ.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsInN1YiI6InVzZXI3ODkiLCJhdWQiOiJocC1wb3J0YWwiLCJleHAiOjE3Mjg5MjcwNTYsImlhdCI6MTcyODkyMzQ1NiwiZW1haWwiOiJib2JAZXhhbXBsZS5jb20iLCJuYW1lIjoiQm9iIFNtaXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYm9iIn0.<signature>
```

**Decoded**:
- **Header**:
  ```json
  {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "rxc1"
  }
  ```
- **Payload**:
  ```json
  {
    "iss": "https://idp.example.com",
    "sub": "user789",
    "aud": "hr-portal",
    "exp": 1728927056,
    "iat": 1728923456,
    "email": "bob@example.com",
    "name": "Bob Smith",
    "preferred_username": "bob"
  }
  ```
- **Signature**: Signed with IdP’s private key.

**Verification in HR Portal** (Python with `pyjwt`):
```python
import jwt
import requests

# Fetch public key from IdP's JWKS endpoint
jwks = requests.get('https://idp.example.com/.well-known/jwks.json').json()
public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwks['keys'][0])

# Verify token
token = "<JWT_from_client>"
try:
    decoded = jwt.decode(token, public_key, algorithms=['RS256'], audience='hr-portal')
    print(f"Welcome, {decoded['name']}!")
except jwt.InvalidTokenError as e:
    print(f"Token verification failed: {e}")
```

**Outcome**: The HR portal verifies the JWT’s signature, issuer (`iss`), audience (`aud`), and expiration. If valid, it trusts the user’s identity (e.g., `email`, `name`) without requiring a separate login. The user seamlessly accesses the expense tracker with the same token.

---

### Key Points Across Examples
- **HS256 vs. RS256**: HS256 uses a shared secret (simpler but requires secure sharing), while RS256 uses public/private keys (better for distributed systems like microservices or SSO).
- **Payload Flexibility**: Include only necessary claims (e.g., `role` for authorization, `email` for SSO) to keep tokens compact.
- **Security**: Always use HTTPS, validate all claims, and set short expiration times with refresh tokens for long sessions.
- **Storage**: Clients typically store JWTs in `localStorage`, `sessionStorage`, or HTTP-only cookies (with `Secure` and `SameSite` flags for security).

If you want to dive deeper into any example (e.g., code for refresh tokens, handling JWT attacks, or integrating with a specific framework), let me know!
