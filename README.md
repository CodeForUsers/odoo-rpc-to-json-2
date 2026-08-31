# JSON/2 API Compatibility Layer — Odoo 19 Standard for Odoo 16, 17 & 18

This module implements the **JSON/2 API** and **JSON-RPC 2.0** specification from **Odoo 19** as a
drop-in compatibility layer for **Odoo 16.0, 17.0, and 18.0** with enterprise-grade security and developer tools.

Modern integrations written against Odoo 19 will work on your current instance without any code changes —
and without touching the legacy XML-RPC protocol.

---

## ✨ Features

| Feature | Details |
|---|---|
| **REST Endpoint** | `POST /json/2/<model>/<method>` — identical to Odoo 19 |
| **JSON-RPC 2.0 Envelope** | `POST /jsonrpc2` — classic wrapper for backward compatibility |
| **Bearer Token Auth** | `Authorization: Bearer <api_key>` header |
| **Multi-DB Support** | `X-Odoo-Database: <db>` header |
| **SHA-256 Key Storage** | API keys are stored as SHA-256 hashes (never in plain text) |
| **High Performance** | Direct hash indexing for O(1) instantaneous key lookup |
| **Model Restrictions** | Restrict API keys to specific models (e.g. only `res.partner`) |
| **Method Restrictions** | Restrict API keys to specific ORM methods (e.g. `search_read,read`) |
| **IP Whitelisting & CIDR** | Restrict API keys to specific IP addresses or subnets (e.g. `10.0.0.0/24`) |
| **Rate Limiting** | Configurable max requests per minute, hour, or day (returns HTTP 429) |
| **CORS & Preflight** | Native `OPTIONS` support for browser SPAs (React, Vue, etc.) |
| **OpenAPI 3.0 Spec** | `GET /json/2/openapi.json` for Swagger UI and client generation |
| **Postman Collection** | `GET /json/2/postman_collection.json` ready to import |
| **Audit Logs & Cleanup** | Execution duration (ms), IP, user, and automated daily log pruning cron |
| **Unit Test Suite** | Full test coverage in `odoo_rpc_to_json_2/tests/` |
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

> **Requirements:** No external Python packages needed. All dependencies (`hmac`, `hashlib`, `secrets`, `ipaddress`, `json`, `logging`) are part of the Python standard library included with Odoo.

---

## 🚀 How to Use

### Step 1 — Generate an API Key

1. Navigate to **JSON-RPC 2.0 › Generate API Key** in the Odoo top menu.
2. Select the **User** whose ACL rules the key will inherit.
3. Enter a descriptive **name** (e.g. `"Shopify Connector"`).
4. Optionally configure:
   - **Expiry Date**: Temporary token expiration.
   - **Allowed Models**: Restrict key access to specific models.
   - **Allowed Methods**: Restrict key access to specific ORM methods (`search_read,read,create`).
   - **Allowed IPs**: Whitelist static IPs or CIDR subnets (`192.168.1.50, 10.0.0.0/24`).
   - **Rate Limiting**: Max allowed requests per minute/hour/day.
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

#### Delete records (`unlink`)
```bash
curl -X POST https://your-odoo.com/json/2/res.partner/unlink \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer jrpc2_your_key_here" \
  -H "X-Odoo-Database: your_db" \
  -d '{
    "ids": [42]
  }'
```

---

### Step 3 — Python Client Example

```python
import requests

BASE_URL = "https://your-odoo.com"
API_KEY = "jrpc2_your_api_key_here"
DATABASE = "your_db"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "X-Odoo-Database": DATABASE,
    "Content-Type": "application/json"
}

# Search partners
response = requests.post(
    f"{BASE_URL}/json/2/res.partner/search_read",
    headers=headers,
    json={
        "domain": [["is_company", "=", True]],
        "fields": ["id", "name", "email"],
        "limit": 10
    }
)

if response.status_code == 200:
    partners = response.json()
    print(f"Found {len(partners)} partners:")
    for p in partners:
        print(f" - [{p['id']}] {p['name']} ({p.get('email', '')})")
else:
    print(f"Error {response.status_code}:", response.json())
```

---

### Step 4 — Interactive Documentation & Schema Introspector

The module automatically exposes live documentation and introspection endpoints:

- **Interactive API Documentation & Swagger UI**: `GET https://your-odoo.com/json/2/docs`
- **Dynamic Model Schema & Payloads**: `GET https://your-odoo.com/json/2/schema/<model_name>` *(e.g. `/json/2/schema/res.partner`)*
- **List Accessible Models**: `GET https://your-odoo.com/json/2/models`
- **OpenAPI 3.0 Specification**: `GET https://your-odoo.com/json/2/openapi.json`
- **Postman Collection**: `GET https://your-odoo.com/json/2/postman_collection.json`

---

## 🧪 Running Unit Tests

Run the automated test suite with the Odoo CLI:

```bash
./odoo-bin -c odoo.conf -d your_test_db -i odoo_rpc_to_json_2 --test-enable --stop-after-init
```

---

## 📄 License & Maintainer

- **License**: LGPL-3
- **Author & Maintainer**: David Carreres Gómez (<david@carreres.es>)
- **Website**: [https://www.carreres.es/](https://www.carreres.es/)
