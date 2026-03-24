# 📚 Memora – Launch Guide

## Dateien

| Datei | Beschreibung |
|-------|-------------|
| `server.js` | Node.js Backend (Express + Stripe + Auth) |
| `index.html` | Frontend (lege in `public/` Ordner) |
| `package.json` | Abhängigkeiten |
| `.env.example` | Vorlage für Umgebungsvariablen |

---

## 1. Lokale Einrichtung

```bash
# Abhängigkeiten installieren
npm install

# .env Datei erstellen
cp .env.example .env
# → .env ausfüllen (Stripe Keys, JWT_SECRET, etc.)

# Frontend in public/ Ordner legen
mkdir public
cp index.html public/

# Server starten
npm start
# → http://localhost:3000
```

---

## 2. Stripe einrichten

1. **Stripe Account** erstellen: https://dashboard.stripe.com
2. **Produkt anlegen**: Dashboard → Products → "+ Add product"
   - Name: `Memora Premium`
   - Preis: `5,99 €` / Monat (recurring)
   - → Price ID kopieren → in `.env` als `STRIPE_PRICE_ID`
3. **API Keys**: Dashboard → Developers → API keys
   - Secret Key → `STRIPE_SECRET_KEY`
4. **Webhook einrichten**: Dashboard → Developers → Webhooks
   - Endpoint URL: `https://deine-domain.de/api/stripe/webhook`
   - Events: `customer.subscription.*`, `invoice.payment_failed`
   - Signing secret → `STRIPE_WEBHOOK_SECRET`

### Lokal testen (Stripe CLI):
```bash
# Stripe CLI installieren: https://stripe.com/docs/stripe-cli
stripe login
stripe listen --forward-to localhost:3000/api/stripe/webhook
```

---

## 3. Deployment (Render.com – empfohlen, kostenlos)

1. GitHub Repo erstellen, alle Dateien pushen
2. https://render.com → "New Web Service"
3. GitHub Repo verbinden
4. Settings:
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Environment**: alle `.env` Variablen eintragen
5. Deploy → URL kopieren → als `CLIENT_URL` in Render eintragen

### Alternativ: Railway, Fly.io, Heroku

---

## 4. Datenbank (für Produktion)

Das aktuelle Backend nutzt In-Memory-Speicher (Daten gehen beim Neustart verloren).

**Für echten Launch**: PostgreSQL oder MongoDB hinzufügen.

Empfehlung: **Supabase** (PostgreSQL, kostenlos)
```
npm install pg
```
Dann `db` Objekte in `server.js` durch echte DB-Queries ersetzen.

---

## 5. Sicherheitsmaßnahmen (bereits implementiert)

| Maßnahme | Details |
|----------|---------|
| **Helmet.js** | HTTP Security Headers (XSS, Clickjacking, MIME) |
| **Rate Limiting** | Login: 10/15min · API: 60/min · Upload: 20/h |
| **bcrypt** | Passwörter mit Cost Factor 12 gehasht |
| **JWT Rotation** | Access Token 15min · Refresh Token 7 Tage · rotiert |
| **httpOnly Cookie** | Refresh Token nicht per JS erreichbar |
| **CORS** | Nur eigene Domain erlaubt |
| **Input Sanitisation** | HTML-Injection verhindert, Max-Length auf allen Feldern |
| **Timing-safe Auth** | Verhindert User-Enumeration beim Login |
| **Webhook Signatur** | Stripe Events kryptografisch verifiziert |
| **Body Size Limit** | Max 50kb pro Request |
| **Stripe serverseitig** | Preise niemals vom Client bestimmt |
| **Premium-Gate** | Alle geschützten Routen serverseitig geprüft |

---

## 6. Success-URL nach Stripe-Zahlung

Stripe leitet nach Zahlung auf:
```
https://deine-domain.de/?session_id={CHECKOUT_SESSION_ID}
```
Das Frontend erkennt das, aktualisiert den Nutzer-Status und blendet die Paywall aus.

---

## Lizenz

MIT – eigene Nutzung & Weiterentwicklung erlaubt.
