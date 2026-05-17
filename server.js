require("dotenv").config();

const express = require("express");
const { auth, requiresAuth } = require("express-openid-connect");

const app = express();
const port = process.env.PORT || 3000;

const requiredEnv = [
  "BASE_URL",
  "ISSUER_BASE_URL",
  "CLIENT_ID",
  "CLIENT_SECRET",
  "SESSION_SECRET"
];

for (const name of requiredEnv) {
  if (!process.env[name]) {
    console.error(`Missing required environment variable: ${name}`);
    process.exit(1);
  }
}

const oidcConfig = {
  authRequired: false,
  idpLogout: true,
  secret: process.env.SESSION_SECRET,
  baseURL: process.env.BASE_URL,
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  issuerBaseURL: process.env.ISSUER_BASE_URL,
  routes: {
    callback: "/callback",
    postLogoutRedirect: "/"
  },
  authorizationParams: {
    response_type: "code",
    scope: "openid profile email"
  }
};

app.use(auth(oidcConfig));

function escapeHtml(value) {
  return String(value ?? "N/A")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function page(title, body) {
  return `
    <!doctype html>
    <html lang="hr">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>${escapeHtml(title)}</title>
        <style>
          body {
            color: #1f2937;
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 40px auto;
            max-width: 900px;
            padding: 0 20px;
          }

          nav {
            margin: 24px 0;
          }

          nav a {
            margin-right: 12px;
          }

          code,
          pre {
            background: #f3f4f6;
            padding: 2px 4px;
          }

          table {
            border-collapse: collapse;
            margin-top: 16px;
            width: 100%;
          }

          th,
          td {
            border: 1px solid #d1d5db;
            padding: 8px;
            text-align: left;
            vertical-align: top;
            word-break: break-word;
          }

          th {
            background: #f3f4f6;
            width: 220px;
          }
        </style>
      </head>
      <body>
        ${body}
      </body>
    </html>
  `;
}

function jsonBlock(value) {
  return `<pre>${escapeHtml(JSON.stringify(value, null, 2))}</pre>`;
}

app.get("/", (req, res) => {
  const isAuthenticated = req.oidc.isAuthenticated();

  res.send(page("OIDC Keycloak PoC", `
    <h1>OIDC autentifikacija s Keycloakom</h1>
    <p>Ovo je jednostavna Express aplikacija koja koristi OpenID Connect autentifikaciju preko Keycloaka.</p>

    <nav>
      <a href="/">Home</a>
      <a href="/profile">Profile</a>
      <a href="/userinfo">UserInfo</a>
      <a href="/admin">Admin</a>
      ${isAuthenticated ? '<a href="/logout">Logout</a>' : '<a href="/login?returnTo=/profile">Login</a>'}
    </nav>

    <h2>Status</h2>
    <p>Korisnik je trenutno: <strong>${isAuthenticated ? "prijavljen" : "nije prijavljen"}</strong></p>
  `));
});

app.get("/profile", requiresAuth(), (req, res) => {
  const user = req.oidc.user || {};

  const claims = {
    sub: user.sub,
    preferred_username: user.preferred_username,
    name: user.name,
    email: user.email,
    email_verified: user.email_verified,
    app_role: user.app_role
  };

  const rows = Object.entries(claims)
    .map(([key, value]) => `
      <tr>
        <th>${escapeHtml(key)}</th>
        <td>${escapeHtml(value)}</td>
      </tr>
    `)
    .join("");

  res.send(page("Profil korisnika", `
    <h1>Profil korisnika</h1>

    <nav>
      <a href="/">Home</a>
      <a href="/profile">Profile</a>
      <a href="/userinfo">UserInfo</a>
      <a href="/admin">Admin</a>
      <a href="/logout">Logout</a>
    </nav>

    <p>Ova stranica dostupna je samo autentificiranim korisnicima.</p>

    <table>
      <thead>
        <tr>
          <th>Claim</th>
          <th>Vrijednost</th>
        </tr>
      </thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  `));
});

app.get("/userinfo", requiresAuth(), async (req, res, next) => {
  try {
    const userInfo = await req.oidc.fetchUserInfo();

    res.send(page("UserInfo podaci", `
      <h1>UserInfo podaci</h1>

      <nav>
        <a href="/">Home</a>
        <a href="/profile">Profile</a>
        <a href="/userinfo">UserInfo</a>
        <a href="/admin">Admin</a>
        <a href="/logout">Logout</a>
      </nav>

      <p>Ova ruta dohvaća korisničke podatke s Keycloak UserInfo endpointa pomoću access tokena.</p>

      ${jsonBlock(userInfo)}
    `));
  } catch (error) {
    next(error);
  }
});

app.get("/admin", requiresAuth(), (req, res) => {
  const user = req.oidc.user || {};

  if (user.app_role !== "admin") {
    return res.status(403).send(page("Zabranjen pristup", `
      <h1>Zabranjen pristup</h1>

      <nav>
        <a href="/">Home</a>
        <a href="/profile">Profile</a>
        <a href="/userinfo">UserInfo</a>
        <a href="/admin">Admin</a>
        <a href="/logout">Logout</a>
      </nav>

      <p>Pristup ovoj ruti dopušten je samo korisnicima koji imaju claim <code>app_role=admin</code>.</p>
      <p>Trenutna vrijednost claima <code>app_role</code>: <strong>${escapeHtml(user.app_role)}</strong></p>
    `));
  }

  res.send(page("Admin dio", `
    <h1>Admin dio aplikacije</h1>

    <nav>
      <a href="/">Home</a>
      <a href="/profile">Profile</a>
      <a href="/userinfo">UserInfo</a>
      <a href="/admin">Admin</a>
      <a href="/logout">Logout</a>
    </nav>

    <p>Ova ruta dostupna je jer prijavljeni korisnik ima claim <code>app_role=admin</code>.</p>
  `));
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    app: "oidc-keycloak-express-lab"
  });
});

app.listen(port, () => {
  console.log(`Express app listening on ${process.env.BASE_URL}`);
});
