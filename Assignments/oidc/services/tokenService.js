const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

function generateIdToken(user, clientId) {
  return jwt.sign(
    {
      iss: process.env.ISSUER,
      sub: user.id,
      aud: clientId,
      exp: now + 3600,
      iat: now,
      email: user.email,
      email_verified: true,
      name: user.email.split('@')[0], // basic name from email
    },
    process.env.ID_TOKEN_SECRET,
    { expiresIn: '1h' }
  );
}

function generateAccessToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email },
    process.env.ACCESS_SECRET,
    { expiresIn: '15m' }
  );
}

function generateRefreshToken(user) {
  return jwt.sign(
    { sub: user.id, jti: uuidv4() },
    process.env.REFRESH_SECRET,
    { expiresIn: '7d' }
  );
}

function verifyAccessToken(token) {
  return jwt.verify(token, process.env.ACCESS_SECRET);
}

function verifyIdToken(token) {
  return jwt.verify(token, process.env.ID_TOKEN_SECRET);
}



module.exports = {
  generateIdToken,
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyIdToken,
};