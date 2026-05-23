# JSON/2 API Compatibility Layer — Odoo 19 Standard for Odoo 16, 17 & 18

This module implements the upcoming **JSON/2 API** and **JSON-RPC 2.0** specification from **Odoo 19** as a
drop-in compatibility layer for **Odoo 16.0, 17.0, and 18.0**.

Modern integrations written against Odoo 19 will work on your current instance without any code changes —
and without touching the legacy XML-RPC protocol.

---

## ✨ Features

| Feature | Details |
|---|---|
| **REST Endpoint** | `POST /json/2/<model>/<method>` — identical to Odoo 19 |
| **JSON-RPC 2.0 Envelope** | `POST /jsonrpc2` — classic wrapper for compatibility |
| **Bearer Token Auth** | `Authorization: Bearer <api_key>` header |
| **Multi-DB Support** | `X-Odoo-Database: <db>` header |
| **SHA-256 Key Storage** | API keys are never stored in plain text |
| **Timing-Safe Validation** | `hmac.compare_digest` — immune to timing oracle attacks |
| **Key Expiration** | Optional per-key expiry dates |
| **Payload Limit** | Configurable via `JSONRPC2_MAX_BODY_BYTES` (default 10 MB) |
| **Audit Logs** | Every call logged: IP, user, duration (ms), status, traceback |
| **Bilingual UI** | Full English + Spanish (`es`) translations |

---

## 📦 Installation

1. Place the `odoo_rpc_to_json_2` folder inside your Odoo `addons` directory.
2. Restart the Odoo service:
   ```bash
   sudo systemctl restart odoo
   # or for development:
   ./odoo-bin -d your_db --addons-path=addons,modules
   ```
3. Enable **Developer Mode** in Odoo (`Settings → General Settings → Developer Tools`).
4. Go to **Apps**, click **Update App List**, search for `JSON/2 API`, and click **Install**.

> **Requirements:** No external Python packages needed. All dependencies (`hmac`, `hashlib`, `secrets`, `json`, `logging`) are part of the Python standard library included with Odoo.

---

## 🚀 How to Use

### Step 1 — Generate an API Key

1. Navigate to **JSON-RPC 2.0 › Generate API Key** in the Odoo top menu.
2. Select the **User** whose ACL rules the key will inherit.
3. Enter a descriptive **name** (e.g. `"Shopify Connector"`).
4. Optionally set an **expiry date**.
5. Click **Generate Key** — copy the key immediately, it is shown **only once**.

> Manage existing keys at **JSON-RPC 2.0 › API Keys**. Archive a key to instantly revoke access.

---

### Step 2 — REST Endpoint `/json/2/` (Odoo 19 style)

**Required headers:**

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `Authorization` | `Bearer <YOUR_API_KEY>` |
| `X-Odoo-Database` | `<your_db>` *(optional if single-db)* |

**The request body** is sent as a flat JSON object with the method arguments:

#### Search records (`search_read`)
```bash
curl -X POST https://your-odoo.com/json/2/res.partner/search_read \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer jrpc2_your_key_here" \
  -H "X-Odoo-Database: your_db" \
  -d '{
    "domain": [["is_company", "=", true]],
    "fields": ["name", "email", "phone"],
    "limit": 5
  }'
```

#### Create a record (`create`)
```bash
curl -X POST https://your-odoo.com/json/2/res.partner/create \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer jrpc2_your_key_here" \
  -H "X-Odoo-Database: your_db" \
  -d '{
    "name": "Integration Partner S.L.",
    "email": "api@integration.com",
    "is_company": true
  }'
```

#### Write / update a record (`write`)
```bash
curl -X POST https://your-odoo.com/json/2/res.partner/write \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer jrpc2_your_key_here" \
  -H "X-Odoo-Database: your_db" \
  -d '{
    "ids": [42],
    "vals": {"phone": "+34 600 000 000"}
  }'
```

---

### Step 3 — JSON-RPC 2.0 Envelope `/jsonrpc2` (legacy wrapper)

Use this endpoint for compatibility with tools that already use the classic JSON-RPC 2.0 structure.
Authentication can be passed either as a **Bearer header** or directly inside the JSON body.

#### With Bearer header (recommended)
```bash
curl -X POST https://your-odoo.com/jsonrpc2 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer jrpc2_your_key_here" \
  -d '{
    "jsonrpc": "2.0",
    "method": "call",
    "id": 1,
    "params": {
      "db": "your_db",
      "model": "res.partner",
      "method": "search_read",
      "args": [[[" is_company", "=", true]]],
      "kwargs": {
        "fields": ["name", "email"],
        "limit": 3
      }
    }
  }'
```

#### With API key in body params
```bash
curl -X POST https://your-odoo.com/jsonrpc2 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "call",
    "id": 1,
    "params": {
      "db": "your_db",
      "api_key": "jrpc2_your_key_here",
      "model": "res.partner",
      "method": "search_read",
      "args": [[]],
      "kwargs": {"fields": ["name"], "limit": 5}
    }
  }'
```

#### With classic username/password (no API key)
```bash
curl -X POST https://your-odoo.com/jsonrpc2 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "call",
    "id": 1,
    "params": {
      "db": "your_db",
      "login": "admin",
      "password": "your_password",
      "model": "res.partner",
      "method": "read",
      "args": [[1], ["name", "email"]]
    }
  }'
```

---

### Step 4 — Monitor with API Logs

Go to **JSON-RPC 2.0 › API Logs** to see a real-time audit panel for every incoming call:

- **Client IP** — the origin of the request
- **User** — the Odoo user the key belongs to
- **Model & Method** — what was called
- **Duration (ms)** — processing time
- **Result** — Success / Error
- **Error Message** — full traceback (visible in Odoo debug mode only)

---

## 🔒 Error Response Format

On failure, `/json/2/` returns a semantic HTTP status code and a consistent JSON body:

| HTTP Code | Meaning |
|---|---|
| `400` | Bad request / validation error |
| `401` | Missing or invalid API key |
| `403` | Access denied (ACL/record rules) |
| `500` | Internal server error |

```json
{
  "name": "odoo.exceptions.AccessError",
  "message": "You do not have permission to access this document.",
  "arguments": ["You do not have permission..."],
  "debug": "<traceback — only shown in Odoo debug mode>"
}
```

---

## 🛡️ Security Notes

- **Keys are stored as SHA-256 hashes** — the plain-text key is never persisted in the database.
- **Timing-safe validation** via `hmac.compare_digest` — prevents timing oracle attacks even with many active keys.
- **Private ORM methods are blocked** — any method starting with `_` is rejected with HTTP 403.
- **Payload size limit** — configurable via the `JSONRPC2_MAX_BODY_BYTES` environment variable (default: 10 MB).

---

## 📋 Compatibility & Support

| Field | Value |
|---|---|
| **Supported versions** | Odoo 16.0, 17.0, 18.0 |
| **External dependencies** | None (pure Python stdlib) |
| **License** | LGPL-3 |
| **Languages** | English, Spanish (`es`) |
| **Maintained by** | David Carreres Gómez |
