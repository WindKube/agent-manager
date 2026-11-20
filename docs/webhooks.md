# Webhooks

The hub posts audited events to HTTPS endpoints a catalog admin registers on the
**Webhooks** screen (or `POST /v1/webhooks`). Every event is an audit row, so
an event exists exactly when its audit-log entry does. The `notifier` worker
role delivers them; it holds no object-store credential and connects as the
`am_notifier` database role.

## Delivery

- `POST` with `Content-Type: application/json`, `User-Agent: agent-manager-webhooks`.
- Delivery is at least once. `Webhook-Id` (equal to the body's `id`) is stable
  across retries; use it to de-duplicate.
- Any 2xx is success. Anything else, a timeout or a connection error is retried
  with exponential backoff (2, 4, 8 … minutes, up to 10 attempts).
- `410 Gone` disables the webhook; enable it again on the screen.
- Only events that happen after a webhook was created are sent to it. The
  dispatcher looks back 24 hours, so a notifier outage longer than that drops
  events.
- The last 100 attempts per webhook are on the screen
  (`GET /v1/webhooks/{id}/deliveries`) and kept for
  `AGENT_MANAGER_WEBHOOK_DELIVERY_RETENTION` (default 30 days).

## Payload

```json
{
  "id": "0193f2a0-0000-7000-8000-0000000000a1",
  "type": "scan.completed",
  "occurredAt": "2026-11-20T08:35:00Z",
  "namespace": "platform",
  "subject": { "kind": "version", "id": "platform/terraform-review@1.4.0" },
  "actor": { "kind": "system", "name": "scanner" },
  "data": { "verdict": "clean", "ruleIds": [], "timedOut": false }
}
```

`namespace` is absent for events about no package (policy, tokens, machines).
A webhook with a namespace filter never receives those. `data` is the audit
row's data and differs per type.

## Event types

| Type | When |
| --- | --- |
| `package.version.registered` | a version was registered and queued for fetching |
| `package.version.stored` | a version's bytes landed (`digest`, `signature`) |
| `package.version.fetch-failed` | a fetch produced no bytes (`reason`) |
| `package.version.deleted` | a version was withdrawn from the catalog |
| `package.deleted` | a package was withdrawn from the catalog |
| `scan.completed` | a scan finished (`verdict`, `ruleIds`, `timedOut`) |
| `finding.accepted` | a finding was accepted (`expiresAt`) |
| `finding.rejected` | a finding was rejected, quarantining its version |
| `waiver.expiring` | an accepted finding lapses within `AGENT_MANAGER_WAIVER_NOTICE` (default 7 days) |
| `waiver.expired` | an accepted finding lapsed and counts against its version again |
| `profile.revision.published` | a profile revision was published |
| `policy.changed` | the organisation policy changed |
| `service-token.created` | a service token was created (`scopes`, `expiresAt`) |
| `service-token.revoked` | a service token was revoked |
| `machine.forgotten` | a machine was removed from the inventory |

Subscribe to `*` for every type, including ones added later.

## Verifying the signature

Signatures follow [Standard Webhooks](https://www.standardwebhooks.com/): the
secret is `whsec_` + base64 of a 32-byte key, and

```
Webhook-Signature: v1,base64(HMAC-SHA256(key, "<Webhook-Id>.<Webhook-Timestamp>.<raw body>"))
```

Verify against the raw body bytes, before any JSON parsing, and reject stale
timestamps:

```go
func verify(secret string, r *http.Request, body []byte) bool {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil {
		return false
	}
	id, ts := r.Header.Get("Webhook-Id"), r.Header.Get("Webhook-Timestamp")
	sent, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || math.Abs(float64(time.Now().Unix()-sent)) > 300 {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + ts + "."))
	mac.Write(body)
	want := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	for _, got := range strings.Fields(r.Header.Get("Webhook-Signature")) {
		if hmac.Equal([]byte(got), []byte(want)) {
			return true
		}
	}
	return false
}
```

Any Standard Webhooks library verifies these as-is. The secret is shown once,
when the webhook is created or its secret rotated; rotating replaces it at
once, so update the receiver straight after.

## Configuration

| Variable | Default | |
| --- | --- | --- |
| `AGENT_MANAGER_WEBHOOK_TIMEOUT` | `10s` | per-attempt request timeout |
| `AGENT_MANAGER_WEBHOOK_DISPATCH_INTERVAL` | `10s` | how often new audit rows are fanned out |
| `AGENT_MANAGER_WEBHOOK_DELIVERY_RETENTION` | `720h` | how long the delivery log is kept |
| `AGENT_MANAGER_WAIVER_CHECK_INTERVAL` | `1h` | how often waivers are checked |
| `AGENT_MANAGER_WAIVER_NOTICE` | `168h` | how far ahead `waiver.expiring` fires |

Receivers must resolve to public addresses, as for package fetches;
`AGENT_MANAGER_OUTBOUND_ALLOWLIST` admits private ones.
