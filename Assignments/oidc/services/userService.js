const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const { users } = require('../db');

async function createUser(email, password) {
  const hashed = await bcrypt.hash(password, 10);
  const user = { id: uuidv4(), email, password: hashed };
  users.push(user);
  return user;
}

function findByEmail(email) {
  return users.find(u => u.email === email);
}

function findById(id) {
  return users.find(u => u.id === id);
}

module.exports = { createUser, findByEmail, findById };