# OIDC Explained

Let's say John is on LinkedIn and clicks _'Login with Google_'. He is now logged it at LinkedIn without that LinkedIn knows his password or really any sensitive data. Great! But how did that work?

Via OpenID Connect (OIDC). This protocol builds on OAuth 2.0 and is the answer to above question.

I will provide a super short and simple summary, a more detailed one and even a code snippet. You should know what OAuth and JWTs are because OIDC builds on them. If you're not familiar with OAuth, see my other guide [here][ref_oauth_repo].

## Super Short Summary

- John clicks _'Login with Google_'
- Now the usual OAuth process takes place
  - John authorizes us to get data about his Google profile
    - E.g. his email, profile picture, name and user id
- **Important**: Google not only sends LinkedIn the access token as specified in OAuth, **but also a JWT.**
- LinkedIn now uses the JWT for authentication in the usual way
  - E.g. John's browser saves the JWT in the cookies and sends it along every request he makes
  - LinkedIn receives the token, verifies it, and knows "ah, this is indeed John"

## More Detailed Summary

Suppose LinkedIn wants users to log in with their Google account to authenticate and retrieve profile info (e.g., name, email).

1. LinkedIn sets up a Google API account and receives a client_id and a client_secret
   - So Google knows this client id is LinkedIn
2. John clicks '_Log in with Google_' on LinkedIn.
3. LinkedIn redirects to Google’s OIDC authorization endpoint:
   https://accounts.google.com/o/oauth2/auth?client_id=...&redirect_uri=...&scope=openid%20profile%20email&response_type=code
   - As you see, LinkedIn passes client_id, redirect_id, scope and response_type as URL params
   - **Important:** scope includes openid (mandatory for OIDC) plus profile and email. It's no longer arbitrary as in OAuth.
   - redirect_uri is where Google sends the response.
4. John logs into Google
5. Google asks: '_LinkedIn wants to access your Google Account_', John clicks '_Allow_'
6. Google redirects to LinkedIn’s redirect_uri with a one-time authorization code:
   https://linkedin.com/oidc/callback?code=one_time_code_xyz
7. LinkedIn makes a server-to-server request and passes the one-time code, client_id, and client_secret **to get an access token and an ID token (a JWT) from Google.**
8. **Finished.** LinkedIn now uses the JWT for authentication and can use the access token to get more info about John's Google account

## Addendum

In step 8 LinkedIn also verifies the JWT's signature and claims. Usually in OIDC we use asymmetric encryption (Google does for example) to sign the JWT. The advantage of asymmetric encryption is that the JWT can be verified by anyone by using the public key, including LinkedIn.

Ideally, Google also returns a refresh token. The JWT will work as long as it's valid, for example hasn't expired. After that, the user will need to redo the above process.

The public keys are usually specified at the JSON Web Key Sets (JWKS) endpoint.

## Key Additions to OAuth 2.0

As we saw, OIDC extends OAuth 2.0. This guide is incomplete, so here are just a few of the additions that I consider key additions.

### ID Token

The ID token is the JWT. It contains user identity data (e.g., sub for user ID, name, email). It's signed by the IdP (Identity provider, in our case Google) and verified by the client (in our case LinkedIn). The JWT is used for authentication. Hence, while OAuth is for authorization, OIDC is authentication.

### Discovery Document

OIDC providers like Google publish a JSON configuration at a standard URL:

`https://accounts.google.com/.well-known/openid-configuration`

This lists endpoints (e.g., authorization, token, UserInfo, JWKS) and supported features (e.g., scopes). LinkedIn can fetch this dynamically to set up OIDC without hardcoding URLs.

### UserInfo Endpoint

OIDC standardizes a UserInfo endpoint (e.g., https://openidconnect.googleapis.com/v1/userinfo). LinkedIn can use the access token to fetch additional user data (e.g., name, picture), ensuring consistency across providers.

### Nonce

To prevent replay attacks, LinkedIn includes a random nonce in the authorization request. Google embeds it in the ID token, and LinkedIn checks it matches during verification.

### Security Notes

- HTTPS: OIDC requires HTTPS for secure token transmission.

- State Parameter: Inherited from OAuth 2.0, it prevents CSRF attacks.

- JWT Verification: LinkedIn must validate JWT claims (e.g., iss, aud, exp, nonce) to ensure security.

## Code Example

Below is a standalone Node.js example using Express to handle OIDC login with Google, storing user data in a SQLite database. Amongst other libraries we use openid-client as it simplies the entire process for us quite a bit.

```javascript
const express = require("express");
const axios = require("axios");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const jwt = require("jsonwebtoken"); // Still using jwt for token verification
const session = require("express-session");

const app = express();
const db = new sqlite3.Database(":memory:");

// Configure session middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET || "oidc-example-secret",
    resave: false,
    saveUninitialized: true,
  })
);

// Initialize database
db.serialize(() => {
  db.run(
    "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT)"
  );
  db.run(
    "CREATE TABLE federated_credentials (user_id INTEGER, provider TEXT, subject TEXT, PRIMARY KEY (provider, subject))"
  );
});

// Configuration
const CLIENT_ID = process.env.OIDC_CLIENT_ID;
const CLIENT_SECRET = process.env.OIDC_CLIENT_SECRET;
const REDIRECT_URI = "https://example.com/oidc/callback";
const ISSUER_URL = "https://accounts.google.com"; // Example OIDC provider

// OIDC discovery endpoints cache
let oidcConfig = null;

// Function to fetch OIDC configuration from the discovery endpoint
async function fetchOIDCConfiguration() {
  if (oidcConfig) return oidcConfig;

  try {
    const response = await axios.get(
      `${ISSUER_URL}/.well-known/openid-configuration`
    );
    oidcConfig = response.data;
    return oidcConfig;
  } catch (error) {
    console.error("Failed to fetch OIDC configuration:", error);
    throw error;
  }
}

// Function to generate and verify PKCE challenge
function generatePKCE() {
  // Generate code verifier (random string between 43-128 chars)
  const codeVerifier = crypto.randomBytes(32).toString("base64url");

  // Generate code challenge (SHA256 hash of verifier, base64url encoded)
  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  return { codeVerifier, codeChallenge };
}

// Function to fetch JWKS (JSON Web Key Set)
async function fetchJWKS() {
  const config = await fetchOIDCConfiguration();
  const response = await axios.get(config.jwks_uri);
  return response.data.keys;
}

// Function to verify ID token
async function verifyIdToken(idToken) {
  // First, decode the header without verification to get the key ID (kid)
  const header = JSON.parse(
    Buffer.from(idToken.split(".")[0], "base64url").toString()
  );

  // Fetch JWKS and find the correct key
  const jwks = await fetchJWKS();
  const signingKey = jwks.find((key) => key.kid === header.kid);

  if (!signingKey) {
    throw new Error("Unable to find signing key");
  }

  // Format key for JWT verification
  // This is a simplified approach, in production you'd use a more robust method
  // to convert JWK to PEM format
  const publicKey = {
    key: signingKey.n,
    e: signingKey.e,
    kty: signingKey.kty,
  };

  return new Promise((resolve, reject) => {
    jwt.verify(
      idToken,
      publicKey,
      {
        algorithms: [signingKey.alg],
        audience: CLIENT_ID,
        issuer: ISSUER_URL,
      },
      (err, decoded) => {
        if (err) return reject(err);
        resolve(decoded);
      }
    );
  });
}

// OIDC login route
app.get("/login", async (req, res) => {
  try {
    // Fetch OIDC configuration
    const config = await fetchOIDCConfiguration();

    // Generate state for CSRF protection
    const state = crypto.randomBytes(16).toString("hex");
    req.session.state = state;

    // Generate nonce for replay protection
    const nonce = crypto.randomBytes(16).toString("hex");
    req.session.nonce = nonce;

    // Generate PKCE code verifier and challenge
    const { codeVerifier, codeChallenge } = generatePKCE();
    req.session.codeVerifier = codeVerifier;

    // Build authorization URL
    const authUrl = new URL(config.authorization_endpoint);
    authUrl.searchParams.append("client_id", CLIENT_ID);
    authUrl.searchParams.append("redirect_uri", REDIRECT_URI);
    authUrl.searchParams.append("response_type", "code");
    authUrl.searchParams.append("scope", "openid profile email");
    authUrl.searchParams.append("state", state);
    authUrl.searchParams.append("nonce", nonce);
    authUrl.searchParams.append("code_challenge", codeChallenge);
    authUrl.searchParams.append("code_challenge_method", "S256");

    res.redirect(authUrl.toString());
  } catch (error) {
    console.error("Login initialization error:", error);
    res.status(500).send("Failed to initialize login");
  }
});

// OIDC callback route
app.get("/oidc/callback", async (req, res) => {
  const { code, state } = req.query;
  const { codeVerifier, state: storedState, nonce: storedNonce } = req.session;

  // Verify state to prevent CSRF
  if (state !== storedState) {
    return res.status(403).send("Invalid state parameter");
  }

  try {
    // Fetch OIDC configuration
    const config = await fetchOIDCConfiguration();

    // Exchange code for tokens
    const tokenResponse = await axios.post(
      config.token_endpoint,
      new URLSearchParams({
        grant_type: "authorization_code",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: codeVerifier,
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    const { id_token, access_token } = tokenResponse.data;

    // Verify ID token
    const claims = await verifyIdToken(id_token);

    // Verify nonce to prevent replay attacks
    if (claims.nonce !== storedNonce) {
      return res.status(403).send("Invalid nonce");
    }

    // Extract user info from ID token
    const { sub: subject, name, email } = claims;

    // If we need more user info, we can fetch it from the userinfo endpoint
    // const userInfoResponse = await axios.get(config.userinfo_endpoint, {
    //   headers: { Authorization: `Bearer ${access_token}` }
    // });
    // const userInfo = userInfoResponse.data;

    // Check if user exists in federated_credentials
    db.get(
      "SELECT * FROM federated_credentials WHERE provider = ? AND subject = ?",
      [ISSUER_URL, subject],
      (err, cred) => {
        if (err) return res.status(500).send("Database error");

        if (!cred) {
          // New user: create account
          db.run(
            "INSERT INTO users (name, email) VALUES (?, ?)",
            [name, email],
            function (err) {
              if (err) return res.status(500).send("Database error");

              const userId = this.lastID;
              db.run(
                "INSERT INTO federated_credentials (user_id, provider, subject) VALUES (?, ?, ?)",
                [userId, ISSUER_URL, subject],
                (err) => {
                  if (err) return res.status(500).send("Database error");

                  // Store user info in session
                  req.session.user = { id: userId, name, email };
                  res.send(`Logged in as ${name} (${email})`);
                }
              );
            }
          );
        } else {
          // Existing user: fetch and log in
          db.get(
            "SELECT * FROM users WHERE id = ?",
            [cred.user_id],
            (err, user) => {
              if (err || !user) return res.status(500).send("Database error");

              // Store user info in session
              req.session.user = {
                id: user.id,
                name: user.name,
                email: user.email,
              };
              res.send(`Logged in as ${user.name} (${user.email})`);
            }
          );
        }
      }
    );
  } catch (error) {
    console.error("OIDC callback error:", error);
    res.status(500).send("OIDC authentication error");
  }
});

// User info endpoint (requires authentication)
app.get("/userinfo", (req, res) => {
  if (!req.session.user) {
    return res.status(401).send("Not authenticated");
  }
  res.json(req.session.user);
});

// Logout endpoint
app.get("/logout", async (req, res) => {
  try {
    // Fetch OIDC configuration to get end session endpoint
    const config = await fetchOIDCConfiguration();
    let logoutUrl;

    if (config.end_session_endpoint) {
      logoutUrl = new URL(config.end_session_endpoint);
      logoutUrl.searchParams.append("client_id", CLIENT_ID);
      logoutUrl.searchParams.append(
        "post_logout_redirect_uri",
        "https://example.com"
      );
    }

    // Clear the session
    req.session.destroy(() => {
      if (logoutUrl) {
        res.redirect(logoutUrl.toString());
      } else {
        res.redirect("/");
      }
    });
  } catch (error) {
    console.error("Logout error:", error);

    // Even if there's an error fetching the config,
    // still clear the session and redirect
    req.session.destroy(() => {
      res.redirect("/");
    });
  }
});

app.listen(3000, () => console.log("Server running on port 3000"));
```

### License

MIT

[ref_oauth_repo]: https://github.com/LukasNiessen/oauth-explained
