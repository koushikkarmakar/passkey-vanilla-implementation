const express = require('express');
const crypto = require('node:crypto');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

// Ensure crypto is available globally
if (!globalThis.crypto) {
  globalThis.crypto = crypto;
}

const PORT = 3000;
const app = express();

app.use(express.static('./public'));
app.use(express.json());

// State stores
const userStore = {};
const challengeStore = {};

// Helper functions
const findUser = (userId, res) => {
  const user = userStore[userId];
  if (!user) {
    res.status(404).json({ error: 'User not found!' });
    return null;
  }
  return user;
};

const handleError = (res, error, status = 400) => {
  console.error(error);
  res.status(status).json({ error: error.message || error });
};

// Register user
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const id = `user_${Date.now()}`;

  userStore[id] = { id, username, password };
  console.log('Registration successful', userStore[id]);

  res.json({ id });
});

// Generate registration challenge
app.post('/register-challenge', async (req, res) => {
  try {
    const { userId } = req.body;
    const user = findUser(userId, res);
    if (!user) return;

    const challengePayload = await generateRegistrationOptions({
      rpID: 'localhost',
      rpName: 'My Localhost Machine',
      attestationType: 'none',
      userName: user.username,
      timeout: 30_000,
    });

    challengeStore[userId] = challengePayload.challenge;
    res.json({ options: challengePayload });
  } catch (error) {
    handleError(res, error);
  }
});

// Verify registration response
app.post('/register-verify', async (req, res) => {
  try {
    const { userId, cred } = req.body;
    const user = findUser(userId, res);
    if (!user) return;

    const challenge = challengeStore[userId];
    const verificationResult = await verifyRegistrationResponse({
      expectedChallenge: challenge,
      expectedOrigin: 'http://localhost:3000',
      expectedRPID: 'localhost',
      response: cred,
    });

    if (!verificationResult.verified) {
      return res.status(400).json({ error: 'Verification failed' });
    }

    user.passkey = verificationResult.registrationInfo;
    res.json({ verified: true });
  } catch (error) {
    handleError(res, error);
  }
});

// Generate login challenge
app.post('/login-challenge', async (req, res) => {
  try {
    const { userId } = req.body;
    const user = findUser(userId, res);
    if (!user) return;

    const opts = await generateAuthenticationOptions({
      rpID: 'localhost',
    });

    challengeStore[userId] = opts.challenge;
    res.json({ options: opts });
  } catch (error) {
    handleError(res, error);
  }
});

// Verify login response
app.post('/login-verify', async (req, res) => {
  try {
    const { userId, cred } = req.body;
    const user = findUser(userId, res);
    if (!user) return;

    const challenge = challengeStore[userId];
    const result = await verifyAuthenticationResponse({
      expectedChallenge: challenge,
      expectedOrigin: 'http://localhost:3000',
      expectedRPID: 'localhost',
      response: cred,
      authenticator: user.passkey,
    });

    if (!result.verified) {
      return res.status(400).json({ error: 'Login failed' });
    }

    // Handle session/cookies/JWT logic
    res.json({ success: true, userId });
  } catch (error) {
    handleError(res, error);
  }
});

// Start the server
app.listen(PORT, () => console.log(`Server started on PORT: ${PORT}`));