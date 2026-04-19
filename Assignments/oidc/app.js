const express = require('express');
require('dotenv').config();

const authRoutes = require('./routes/auth');
const oidcRoutes = require('./routes/oidc');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/auth', authRoutes);
app.use('/oidc', oidcRoutes);

app.listen(process.env.PORT, () => {
  console.log(`🚀 Server running on http://localhost:${process.env.PORT}`);
});