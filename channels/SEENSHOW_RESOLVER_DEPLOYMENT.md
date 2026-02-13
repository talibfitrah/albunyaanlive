# Seenshow Resolver Deployment Notes

## Required credential file

`seenshow_resolver.js` requires a credentials file with real account secrets.
For production service installs, place it at:

`/etc/albunyaan/seenshow_credentials.json`

Use `channels/seenshow_credentials.example.json` as the template.

## Permissions

Set strict file permissions:

```bash
chmod 600 /etc/albunyaan/seenshow_credentials.json
chown msa:msa /etc/albunyaan/seenshow_credentials.json
```

## Service expectations

- `channels/seenshow-resolver.service` points to:
  - `SEENSHOW_CREDENTIALS_FILE=/etc/albunyaan/seenshow_credentials.json`
  - `SEENSHOW_RESOLVER_HOST=127.0.0.1`
  - `SEENSHOW_RESOLVER_PORT=8090`
- `try_start_stream.sh` and `provider_sync.js` both consume the resolver over `http://127.0.0.1:8090` by default.

## Health checks

```bash
curl -sS http://127.0.0.1:8090/health
curl -sS http://127.0.0.1:8090/token-status
```

Expected healthy shape:

- `"authenticated": true`
- token counts show cached/valid entries
- slots show bounded concurrent usage
