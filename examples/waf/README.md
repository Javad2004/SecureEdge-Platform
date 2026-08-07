# WAF Demonstration

This example shows SecurityEdge allowing normal application traffic and blocking common malicious input patterns before they reach EdgeProxy or the Origin.

Start the standard local stack from the [examples index](../README.md), then execute [`requests.http`](./requests.http) one request at a time.

## Expected behavior

| Request | Expected result |
| --- | --- |
| Normal `/api/products` request | `200 OK`, `X-Security-Action: ALLOW` |
| SQL-injection payload in JSON body | `403 Forbidden`, `X-Security-Action: BLOCK` |
| Encoded XSS payload in query string | `403 Forbidden`, `X-Security-Action: BLOCK` |
| Security logs query | Recent events include `waf_blocked` entries after the blocked requests |

The demonstration payloads match categories covered by the built-in WAF test suite and are sent only to the local `origin-demo` stack.

## curl.exe equivalents

Normal request:

```powershell
curl.exe -i http://127.0.0.1:8081/api/products
```

SQL-injection demonstration:

```powershell
curl.exe -i `
  -X POST `
  -H "Content-Type: application/json" `
  --data-raw '{"username":"admin'' OR 1=1 --"}' `
  http://127.0.0.1:8081/login
```

Encoded XSS demonstration:

```powershell
curl.exe -i "http://127.0.0.1:8081/search?q=%3Cscript%3Ejavascript%3Aalert%281%29%3C%2Fscript%3E"
```

Inspect recent security events:

```powershell
curl.exe -sS `
  -H "Authorization: Bearer dev-security-token" `
  "http://127.0.0.1:9191/api/v1/logs?limit=20"
```

Do not use these security-test payloads against third-party services or systems you are not authorized to test.
