const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const userService = require('../services/userService');
const tokenService = require('../services/tokenService');
const { authCodes } = require('../db');

const CLIENTS = {
  my_client: {
    clientId: 'my_client',
    clientSecret: 'supersecret',
    redirectUris: ['http://localhost:3000/callback'],
  },
};

// GET /oidc/.well-known/openid-configuration
router.get('/.well-known/openid-configuration', (req, res) => {
  const issuer = process.env.ISSUER;
  res.json({
    issuer,
    authorization_endpoint: `${issuer}/oidc/auth`,
    token_endpoint: `${issuer}/oidc/token`,
    userinfo_endpoint: `${issuer}/oidc/userinfo`,
    jwks_uri: `${issuer}/oidc/jwks`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['HS256'],
    scopes_supported: ['openid', 'email', 'profile'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'email', 'email_verified', 'name'],
  });
});

// GET /oidc/auth
router.get('/auth', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state } = req.query;

  const client = CLIENTS[client_id];
  if (!client) return res.status(400).send('Unknown client');
  if (!client.redirectUris.includes(redirect_uri)) return res.status(400).send('Invalid redirect_uri');
  if (response_type !== 'code') return res.status(400).send('Unsupported response_type');

  return res.redirect(
    `/oidc/login?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}&scope=${scope}&state=${state || ''}`
  );
});

// GET /oidc/login
router.get('/login', (req, res) => {
  const { client_id, redirect_uri, scope, state } = req.query;
  res.send(`
    <h2>Login</h2>
    <form method="POST" action="/oidc/login">
      <input type="hidden" name="client_id" value="${client_id}" />
      <input type="hidden" name="redirect_uri" value="${redirect_uri}" />
      <input type="hidden" name="scope" value="${scope}" />
      <input type="hidden" name="state" value="${state || ''}" />
      <input name="email" placeholder="Email" required /><br/>
      <input name="password" type="password" placeholder="Password" required /><br/>
      <button type="submit">Login</button>
    </form>
  `);
});

// POST /oidc/login
router.post('/login', async (req, res) => {
  const { email, password, client_id, redirect_uri, scope, state } = req.body;

  const user = userService.findByEmail(email);
  if (!user) return res.status(400).send('Invalid credentials');

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).send('Invalid credentials');

  return res.redirect(
    `/oidc/consent?user_id=${user.id}&client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}&scope=${scope}&state=${state || ''}`
  );
});

// GET /oidc/consent
router.get('/consent', (req, res) => {
  const { user_id, client_id, redirect_uri, scope, state } = req.query;
  res.send(`
    <h2>Consent</h2>
    <p><strong>${client_id}</strong> wants access to: <strong>${scope}</strong></p>
    <form method="POST" action="/oidc/consent">
      <input type="hidden" name="user_id" value="${user_id}" />
      <input type="hidden" name="client_id" value="${client_id}" />
      <input type="hidden" name="redirect_uri" value="${redirect_uri}" />
      <input type="hidden" name="scope" value="${scope}" />
      <input type="hidden" name="state" value="${state || ''}" />
      <button type="submit">Allow</button>
    </form>
  `);
});

// POST /oidc/consent
router.post('/consent', (req, res) => {
  const { user_id, client_id, redirect_uri, scope, state } = req.body;

  const code = uuidv4();
  authCodes.push({
    code,
    user_id,
    client_id,
    redirect_uri,
    scope,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });

  console.log('✅ Auth code issued:', code);

  const redirectUrl = `${redirect_uri}?code=${code}${state ? `&state=${state}` : ''}`;
  return res.redirect(redirectUrl);
});

// POST /oidc/token
router.post('/token', async (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  const client = CLIENTS[client_id];
  if (!client || client.clientSecret !== client_secret) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  const codeIndex = authCodes.findIndex(c => c.code === code);
  if (codeIndex === -1) return res.status(400).json({ error: 'invalid_code' });

  const authCode = authCodes[codeIndex];
  if (authCode.expiresAt < Date.now()) {
    authCodes.splice(codeIndex, 1);
    return res.status(400).json({ error: 'code_expired' });
  }
  if (authCode.redirect_uri !== redirect_uri) {
    return res.status(400).json({ error: 'redirect_uri_mismatch' });
  }

  authCodes.splice(codeIndex, 1);

  const user = userService.findById(authCode.user_id);
  if (!user) return res.status(400).json({ error: 'user_not_found' });

  const accessToken = tokenService.generateAccessToken(user);
  const refreshToken = tokenService.generateRefreshToken(user);
  const idToken = tokenService.generateIdToken(user, client_id, authCode.scope);

  console.log('✅ Tokens issued for:', user.email);

  // ✅ Google-like response
  return res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: authCode.scope,
    id_token: idToken,
    refresh_token: refreshToken,
  });
});

// GET /oidc/userinfo
router.get('/userinfo', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.sendStatus(401);

  const token = auth.split(' ')[1];

  try {
    const payload = tokenService.verifyAccessToken(token);
    const user = userService.findById(payload.sub);
    if (!user) return res.sendStatus(404);
    return res.json({
      sub: user.id,
      email: user.email,
      email_verified: true,
      name: user.email.split('@')[0],
    });
  } catch {
    return res.sendStatus(401);
  }
});

module.exports = router;