# Love AI — Analytics & Insights Service

Secure forecasting and business insights for Love Laundry, reading the same
MongoDB main database as `laundry-management`.

## Capabilities

| Endpoint | Description |
|---|---|
| `GET /api/ai/health` | Health check (signed) |
| `GET /api/ai/insights/dashboard` | Combined revenue / expenses / payroll + 3-month forecasts |
| `GET /api/ai/insights/revenue` | Revenue series, trend forecast, top customers |
| `GET /api/ai/insights/expenses` | Expense series, forecast, top categories |
| `GET /api/ai/insights/salary` | Payroll series, forecast, top employees |
| `GET /api/ai/insights/payroll-risk` | Employees holding outstanding advances |
| `POST /api/ai/insights/query` | Structured query `{metric, months}` |

## Security model

- **Hashed API keys** — each request sends `X-API-Key`. The service compares
  HMAC-SHA256 hashes in constant time; the plaintext key is never stored.
- **Request signatures** — insight routes require
  `X-Timestamp` (unix seconds, `±SIGNATURE_TTL_SECONDS`), `X-Body-Hash`
  (SHA-256 of the raw body, `""` for GET) and
  `X-Signature` = `HMAC_SHA256(api_key, "<METHOD>\n<PATH>\n<TS>\n<BODY_HASH>")`.
  This binds *who is asking*, *what they ask*, and *when* — blocking tampering
  and replay attacks.
- **Data at rest** — PII is envelope-encrypted with **AES-256-GCM** (same
  `MASTER_KEY` as `laundry-management`), unwrapped per document with a
  KEK-wrapped DEK.
- **Data integrity** — every response includes a `data_hash` (SHA-256) so the
  client can verify the payload was not altered in transit.
- **Transport** — rate limiting, strict CORS, and security headers
  (`nosniff`, `DENY` framing, HSTS, `X-Request-Id`).

## Env vars (see `.env.example`)

- `MONGO_URI`, `MONGO_DB_NAME` (or `MONGODB_MAIN_URI`, `MONGODB_MAIN_DB`)
- `MASTER_KEY` — **must match `laundry-management`**
- `LOVE_AI_API_KEYS` — comma-separated API keys
- `JWT_SECRET` — optional, for user-service JWT passthrough attribution
- `SIGNATURE_TTL_SECONDS`, `RATE_LIMIT_PER_MINUTE`, `CORS_ORIGINS`

## Signing a request (client example)

```python
import hmac, hashlib, json, time, urllib.request

key = "your-api-key"
ts = str(int(time.time()))
body = b""
body_hash = hashlib.sha256(body).hexdigest()
canonical = "\n".join(["GET", "/api/ai/insights/dashboard", ts, body_hash])
sig = hmac.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()

req = urllib.request.Request(
    "https://<host>/api/ai/insights/dashboard?months=6",
    headers={
        "X-API-Key": key,
        "X-Timestamp": ts,
        "X-Body-Hash": body_hash,
        "X-Signature": sig,
    },
)
```