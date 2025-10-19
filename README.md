# token
A [maubot](https://github.com/maubot/maubot) to manage your MAS user registration tokens.

(forked from https://github.com/yoxcu/maubot-token/tree/main)

## Building

Use the included worker helper to package the plugin into a `.mbp` archive:

```bash
./worker build
```

The archive is written to `dist/`.

## Commands

- `!token list [token]` shows every token reachable via MAS or details for a specific token or ULID.
- `!token generate [uses] [expiry]` creates a token; omit values to fall back to `default_uses_allowed` and `default_expiry_time` (seconds) from the config.
- `!token delete <token>` revokes a token using either its string or ULID; the reply includes its latest MAS status.
- `!token unrevoke <token>` restores a previously revoked token so it can be used again if MAS marks it valid.

All commands require the sender to appear in `whitelist`.

## Configuration

- `admin_api` must point at your MAS admin base URL, e.g. `https://mas.example.com/api/admin`.
- `whitelist` lists individual Matrix IDs allowed to use the bot anywhere; `room_whitelist` lists room IDs where anyone present may use the commands.
- `token_url`, `client_id`, and `client_secret` let the bot fetch MAS admin tokens automatically (see the quick guide below).
- `default_uses_allowed` and `default_expiry_time` act as fallbacks when `generate` arguments are omitted.
- `base_command` allows renaming the root command if `!token` conflicts with other bots.

### Quick guide: MAS token for automated tools

Follow these five small steps to give the bot MAS admin access without touching any interactive flows.

**Step 1 – Generate a client ID and secret**

Run once on any machine with Python:

```bash
python3 - <<'PY'
import secrets
alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
client_id = "".join(secrets.choice(alphabet) for _ in range(26))
client_secret = secrets.token_urlsafe(32)
print(f"CLIENT_ID={client_id}")
print(f"CLIENT_SECRET={client_secret}")
PY
```

Copy the two lines that are printed; you will paste them in the next steps.

**Step 2 – Add the client to MAS**

Open your MAS configuration file (often `/etc/mas/config.yaml`) and add the client by hand:

```yaml
clients:
  - client_id: "PASTE_CLIENT_ID_HERE"
    client_auth_method: client_secret_basic
    client_secret: "PASTE_CLIENT_SECRET_HERE"
    grants:
      - client_credentials
    scopes:
      - "urn:mas:admin"

policy:
  data:
    admin_clients:
      - "PASTE_CLIENT_ID_HERE"
```

Append to existing `clients` or `policy.data.admin_clients` lists instead of duplicating keys.

**Step 3 – Expose the admin API (skip if already configured)**

Ensure at least one listener lists the `adminapi` resource:

```yaml
http:
  listeners:
    - name: web
      resources:
        - name: discovery
        - name: adminapi
      binds:
        - address: "[::]:8080"
```

**Step 4 – Restart MAS**

Reload or restart the service so the new client is picked up (for example `systemctl restart mas`), then run `mas-cli config sync` (inside your container if you use Docker) so the database reflects the new client settings.

**Step 5 – Point the bot at MAS**

- Set `token_url`, `client_id`, `client_secret`, and `token_scope` (usually `urn:mas:admin`) in `base-config.yaml`.
- Optional but recommended: verify the credentials still work with a direct token request and a test call:

  ```bash
  MAS_BASE=https://mas.example.com
  CLIENT_ID=the_value_you_generated
  CLIENT_SECRET=the_value_you_generated

  ACCESS_TOKEN=$(
    curl -s \
      -u "$CLIENT_ID:$CLIENT_SECRET" \
      -d "grant_type=client_credentials&scope=urn:mas:admin" \
      "$MAS_BASE/oauth2/token" | jq -r '.access_token'
  )

  curl -H "Authorization: Bearer $ACCESS_TOKEN" \
    "$MAS_BASE/api/admin/v1/user-registration-tokens"
  ```

The bot will use these credentials to fetch and refresh short-lived access tokens automatically.
- Optional: list room IDs under `room_whitelist` if you want everyone in specific rooms to use the bot without adding each user to `whitelist`.

