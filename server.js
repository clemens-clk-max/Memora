/**
 * MEMORA – Backend Server
 * Node.js + Express + Stripe
 *
 * SETUP:
 *   npm install express stripe bcryptjs jsonwebtoken helmet express-rate-limit cors cookie-parser uuid dotenv
 *   node server.js
 *
 * .env file (create in same folder):
 *   STRIPE_SECRET_KEY=sk_live_...
 *   STRIPE_WEBHOOK_SECRET=whsec_...
 *   STRIPE_PRICE_ID=price_...
 *   JWT_SECRET=some_long_random_string_min_32_chars
 *   CLIENT_URL=https://yourdomain.com
 *   PORT=3000
 */

'use strict';

require('dotenv').config();

const express      = require('express');
const stripe       = require('stripe')(process.env.STRIPE_SECRET_KEY);
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const cors         = require('cors');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const path         = require('path');

const app = express();

// ─────────────────────────────────────────────────────────────
// IN-MEMORY DATABASE (replace with PostgreSQL/MongoDB in prod)
// ─────────────────────────────────────────────────────────────
const db = {
  users: [],          // { id, email, passwordHash, name, createdAt, trialStart, stripeCustomerId, subscriptionId, subscriptionStatus, subscriptionEnd }
  cards: [],          // { id, userId, deckName, deckIcon, question, answer, explanation, isPublic, likes, createdAt }
  refreshTokens: new Set(),
};

// ─────────────────────────────────────────────────────────────
// SECURITY MIDDLEWARE
// ─────────────────────────────────────────────────────────────

// Helmet sets security headers (XSS, clickjacking, MIME sniff, etc.)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "https://js.stripe.com"],
      frameSrc:    ["https://js.stripe.com", "https://hooks.stripe.com"],
      connectSrc:  ["'self'", "https://api.stripe.com"],
      styleSrc:    ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:     ["'self'", "https://fonts.gstatic.com"],
      imgSrc:      ["'self'", "data:"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// CORS – only allow your frontend domain
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (same-origin, Postman, etc.)
    if (!origin) return callback(null, true);
    const allowed = [
      process.env.CLIENT_URL,
      'http://localhost:3000',
    ].filter(Boolean);
    // Also allow any onrender.com subdomain during development
    if (allowed.includes(origin) || origin.endsWith('.onrender.com')) {
      return callback(null, true);
    }
    return callback(new Error('CORS: origin not allowed'));
  },
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));

app.use(cookieParser());

// Parse JSON (but NOT for Stripe webhooks – they need raw body)
app.use((req, res, next) => {
  if (req.originalUrl === '/api/stripe/webhook') next();
  else express.json({ limit: '50kb' })(req, res, next);  // 50kb max body
});

// ─────────────────────────────────────────────────────────────
// RATE LIMITERS
// ─────────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 10,                   // max 10 attempts per IP
  message: { error: 'Zu viele Versuche. Bitte warte 15 Minuten.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 min
  max: 60,
  message: { error: 'Zu viele Anfragen. Bitte warte kurz.' },
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20,
  message: { error: 'Upload-Limit erreicht (20/Stunde).' },
});

// ─────────────────────────────────────────────────────────────
// JWT HELPERS
// ─────────────────────────────────────────────────────────────
const JWT_SECRET      = process.env.JWT_SECRET;
const ACCESS_TTL      = '15m';
const REFRESH_TTL     = '7d';
const TRIAL_DAYS      = 7;
const PRICE_ID        = process.env.STRIPE_PRICE_ID;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('❌  JWT_SECRET must be set and at least 32 characters!');
  process.exit(1);
}

function signAccess(userId) {
  return jwt.sign({ sub: userId, type: 'access' }, JWT_SECRET, { expiresIn: ACCESS_TTL });
}

function signRefresh(userId) {
  const token = jwt.sign({ sub: userId, type: 'refresh', jti: uuidv4() }, JWT_SECRET, { expiresIn: REFRESH_TTL });
  db.refreshTokens.add(token);
  return token;
}

// ─────────────────────────────────────────────────────────────
// AUTH MIDDLEWARE
// ─────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') && authHeader.slice(7);
  if (!token) return res.status(401).json({ error: 'Nicht authentifiziert.' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.type !== 'access') return res.status(401).json({ error: 'Ungültiger Token-Typ.' });
    req.userId = payload.sub;
    next();
  } catch (e) {
    if (e.name === 'TokenExpiredError') return res.status(401).json({ error: 'Token abgelaufen.', code: 'TOKEN_EXPIRED' });
    return res.status(401).json({ error: 'Ungültiger Token.' });
  }
}

// Premium = active subscription OR within trial period
function requirePremium(req, res, next) {
  const user = db.users.find(u => u.id === req.userId);
  if (!user) return res.status(401).json({ error: 'Nutzer nicht gefunden.' });

  const now = Date.now();
  const trialEnd = user.trialStart + TRIAL_DAYS * 86400000;
  const inTrial = now < trialEnd;
  const hasSub   = user.subscriptionStatus === 'active' || user.subscriptionStatus === 'trialing';

  if (inTrial || hasSub) return next();
  return res.status(403).json({ error: 'Premium erforderlich.', code: 'PREMIUM_REQUIRED' });
}

// ─────────────────────────────────────────────────────────────
// INPUT SANITISATION HELPER
// ─────────────────────────────────────────────────────────────
function sanitise(str, maxLen = 500) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen).replace(/[<>]/g, ''); // strip < > to prevent HTML injection
}

// ─────────────────────────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────────────────────────

// POST /api/auth/register
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const email = sanitise(req.body.email, 254).toLowerCase();
    const name  = sanitise(req.body.name,  100);
    const pass  = req.body.password;

    // Validate
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'Ungültige E-Mail-Adresse.' });
    if (!pass || pass.length < 8)
      return res.status(400).json({ error: 'Passwort muss mindestens 8 Zeichen haben.' });
    if (pass.length > 128)
      return res.status(400).json({ error: 'Passwort zu lang.' });
    if (db.users.find(u => u.email === email))
      return res.status(409).json({ error: 'E-Mail bereits registriert.' });

    const passwordHash = await bcrypt.hash(pass, 12);
    const user = {
      id: uuidv4(),
      email,
      name: name || email.split('@')[0],
      passwordHash,
      createdAt: Date.now(),
      trialStart: Date.now(),
      stripeCustomerId: null,
      subscriptionId: null,
      subscriptionStatus: null,
      subscriptionEnd: null,
    };
    db.users.push(user);

    const access  = signAccess(user.id);
    const refresh = signRefresh(user.id);

    // Refresh token in httpOnly cookie (not accessible via JS)
    res.cookie('refreshToken', refresh, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(201).json({
      accessToken: access,
      user: publicUser(user),
    });
  } catch (e) {
    console.error('Register error:', e);
    return res.status(500).json({ error: 'Serverfehler.' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const email = sanitise(req.body.email, 254).toLowerCase();
    const pass  = req.body.password;

    // Constant-time user lookup to prevent timing attacks
    const user = db.users.find(u => u.email === email);
    const dummyHash = '$2a$12$invalidhashfortiminginvalidhash00000000000000000000';
    const match = await bcrypt.compare(pass || '', user ? user.passwordHash : dummyHash);

    if (!user || !match)
      return res.status(401).json({ error: 'E-Mail oder Passwort falsch.' });

    const access  = signAccess(user.id);
    const refresh = signRefresh(user.id);

    res.cookie('refreshToken', refresh, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({ accessToken: access, user: publicUser(user) });
  } catch (e) {
    console.error('Login error:', e);
    return res.status(500).json({ error: 'Serverfehler.' });
  }
});

// POST /api/auth/refresh
app.post('/api/auth/refresh', (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token || !db.refreshTokens.has(token))
    return res.status(401).json({ error: 'Ungültiger Refresh-Token.' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.type !== 'refresh') return res.status(401).json({ error: 'Ungültiger Token-Typ.' });

    // Rotate: invalidate old, issue new
    db.refreshTokens.delete(token);
    const newRefresh = signRefresh(payload.sub);
    const newAccess  = signAccess(payload.sub);

    res.cookie('refreshToken', newRefresh, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({ accessToken: newAccess });
  } catch (e) {
    db.refreshTokens.delete(token);
    return res.status(401).json({ error: 'Token abgelaufen. Bitte neu einloggen.' });
  }
});

// POST /api/auth/logout
app.post('/api/auth/logout', (req, res) => {
  const token = req.cookies.refreshToken;
  if (token) db.refreshTokens.delete(token);
  res.clearCookie('refreshToken');
  return res.json({ ok: true });
});

// GET /api/auth/me
app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = db.users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: 'Nutzer nicht gefunden.' });
  return res.json({ user: publicUser(user) });
});

function publicUser(user) {
  const now = Date.now();
  const trialEnd = user.trialStart + TRIAL_DAYS * 86400000;
  const inTrial  = now < trialEnd;
  const daysLeft = Math.max(0, Math.ceil((trialEnd - now) / 86400000));
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    trialEnd,
    inTrial,
    trialDaysLeft: daysLeft,
    subscriptionStatus: user.subscriptionStatus,
    isPremium: inTrial || user.subscriptionStatus === 'active' || user.subscriptionStatus === 'trialing',
  };
}

// ─────────────────────────────────────────────────────────────
// STRIPE ROUTES
// ─────────────────────────────────────────────────────────────

// POST /api/stripe/checkout  – create checkout session
app.post('/api/stripe/checkout', requireAuth, apiLimiter, async (req, res) => {
  try {
    const user = db.users.find(u => u.id === req.userId);
    if (!user) return res.status(404).json({ error: 'Nutzer nicht gefunden.' });

    // Create or reuse Stripe customer
    let customerId = user.stripeCustomerId;
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: user.email,
        name: user.name,
        metadata: { userId: user.id },
      });
      customerId = customer.id;
      user.stripeCustomerId = customerId;
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: PRICE_ID, quantity: 1 }],
      success_url: `${process.env.CLIENT_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:  `${process.env.CLIENT_URL}/pricing`,
      // Prevent re-use of sessions (security: each session is single-use)
      client_reference_id: user.id,
      metadata: { userId: user.id },
    });

    return res.json({ url: session.url });
  } catch (e) {
    console.error('Checkout error:', e);
    return res.status(500).json({ error: 'Zahlungssession konnte nicht erstellt werden.' });
  }
});

// POST /api/stripe/portal  – customer portal for managing subscription
app.post('/api/stripe/portal', requireAuth, apiLimiter, async (req, res) => {
  try {
    const user = db.users.find(u => u.id === req.userId);
    if (!user || !user.stripeCustomerId)
      return res.status(400).json({ error: 'Kein Stripe-Konto gefunden.' });

    const session = await stripe.billingPortal.sessions.create({
      customer: user.stripeCustomerId,
      return_url: `${process.env.CLIENT_URL}/settings`,
    });
    return res.json({ url: session.url });
  } catch (e) {
    return res.status(500).json({ error: 'Portal konnte nicht geöffnet werden.' });
  }
});

// POST /api/stripe/webhook  – Stripe event handler (raw body required!)
app.post('/api/stripe/webhook',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (e) {
      console.error('Webhook signature failed:', e.message);
      return res.status(400).send(`Webhook Error: ${e.message}`);
    }

    const data = event.data.object;

    switch (event.type) {
      case 'customer.subscription.created':
      case 'customer.subscription.updated': {
        const user = db.users.find(u => u.stripeCustomerId === data.customer);
        if (user) {
          user.subscriptionId     = data.id;
          user.subscriptionStatus = data.status;           // 'active', 'past_due', etc.
          user.subscriptionEnd    = data.current_period_end * 1000;
        }
        break;
      }
      case 'customer.subscription.deleted': {
        const user = db.users.find(u => u.stripeCustomerId === data.customer);
        if (user) {
          user.subscriptionStatus = 'canceled';
          user.subscriptionEnd    = Date.now();
        }
        break;
      }
      case 'invoice.payment_failed': {
        const user = db.users.find(u => u.stripeCustomerId === data.customer);
        if (user) user.subscriptionStatus = 'past_due';
        break;
      }
    }

    res.json({ received: true });
  }
);

// ─────────────────────────────────────────────────────────────
// COMMUNITY LIBRARY ROUTES (Premium only)
// ─────────────────────────────────────────────────────────────

// GET /api/library  – get public cards
app.get('/api/library', requireAuth, requirePremium, apiLimiter, (req, res) => {
  const search = sanitise(req.query.search || '', 100).toLowerCase();
  const topic  = sanitise(req.query.topic  || '', 100);
  const page   = Math.max(1, parseInt(req.query.page) || 1);
  const limit  = 20;

  let cards = db.cards.filter(c => c.isPublic);

  if (search) cards = cards.filter(c =>
    c.question.toLowerCase().includes(search) ||
    c.deckName.toLowerCase().includes(search)
  );
  if (topic) cards = cards.filter(c => c.deckName === topic);

  // Sort newest first
  cards.sort((a, b) => b.createdAt - a.createdAt);

  const total = cards.length;
  const items = cards.slice((page - 1) * limit, page * limit).map(c => ({
    id:          c.id,
    deckName:    c.deckName,
    deckIcon:    c.deckIcon,
    question:    c.question,
    answer:      c.answer,
    explanation: c.explanation,
    authorName:  db.users.find(u => u.id === c.userId)?.name || 'Anonym',
    likes:       c.likes,
    createdAt:   c.createdAt,
  }));

  return res.json({ items, total, page, pages: Math.ceil(total / limit) });
});

// POST /api/library/upload  – upload card to library
app.post('/api/library/upload', requireAuth, requirePremium, uploadLimiter, (req, res) => {
  const deckName    = sanitise(req.body.deckName,    80);
  const deckIcon    = sanitise(req.body.deckIcon,     4);
  const question    = sanitise(req.body.question,   300);
  const answer      = sanitise(req.body.answer,     300);
  const explanation = sanitise(req.body.explanation,300);

  if (!deckName || !question || !answer)
    return res.status(400).json({ error: 'Thema, Frage und Antwort sind Pflichtfelder.' });

  // Duplicate check: same user, same question
  const exists = db.cards.find(c => c.userId === req.userId && c.question === question);
  if (exists) return res.status(409).json({ error: 'Diese Karte hast du bereits hochgeladen.' });

  const card = {
    id:          uuidv4(),
    userId:      req.userId,
    deckName,
    deckIcon:    deckIcon || '📚',
    question,
    answer,
    explanation,
    isPublic:    true,
    likes:       0,
    createdAt:   Date.now(),
  };
  db.cards.push(card);
  return res.status(201).json({ ok: true, id: card.id });
});

// POST /api/library/:id/like
app.post('/api/library/:id/like', requireAuth, requirePremium, apiLimiter, (req, res) => {
  const card = db.cards.find(c => c.id === req.params.id && c.isPublic);
  if (!card) return res.status(404).json({ error: 'Karte nicht gefunden.' });
  card.likes++;
  return res.json({ likes: card.likes });
});

// GET /api/library/topics
app.get('/api/library/topics', requireAuth, requirePremium, (req, res) => {
  const topics = [...new Set(db.cards.filter(c => c.isPublic).map(c => c.deckName))].sort();
  return res.json({ topics });
});

// ─────────────────────────────────────────────────────────────
// SERVE FRONTEND
// ─────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public'), {
  // Prevent directory traversal
  dotfiles: 'deny',
  index: false,
}));

// SPA fallback – only serve index.html for non-API routes
app.get(/^(?!\/api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─────────────────────────────────────────────────────────────
// 404 + ERROR HANDLER
// ─────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Endpunkt nicht gefunden.' }));

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  // Never leak stack traces to client
  res.status(500).json({ error: 'Interner Serverfehler.' });
});

// ─────────────────────────────────────────────────────────────
// START
// ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅  Memora server running on port ${PORT}`));
