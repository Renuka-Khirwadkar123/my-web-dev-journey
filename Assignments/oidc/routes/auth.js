const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const userService = require('../services/userService');

// Register
router.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (userService.findByEmail(email)) {
    return res.status(400).json({ error: 'User already exists' });
  }
  const user = await userService.createUser(email, password);
  res.json({ id: user.id, email: user.email });
});

module.exports = router;