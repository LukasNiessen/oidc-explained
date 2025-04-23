const express = require("express");
const axios = require("axios");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const session = require("express-session");
const jwkToPem = require("jwk-to-pem");

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
const ISSUER_URL = "https://accounts.google.com";

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
  // Generate code verifier
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

// Function to fetch JWKS
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
  const publicKey = jwkToPem(signingKey);

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

  // Verify state
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

    // Verify nonce
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
