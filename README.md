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
- `access_token` requires an MAS admin API token (see MAS docs for issuing and scoping).
- `default_uses_allowed` and `default_expiry_time` act as fallbacks when `generate` arguments are omitted.
- `base_command` allows renaming the root command if `!token` conflicts with other bots.

### Create an MAS admin API token

1. Define an OAuth client in the MAS configuration with `scope: urn:mas:admin` and add its `client_id` under `policy.data.admin_clients`.  
2. Restart MAS (or reload the config) so the new client policy takes effect.  
3. Exchange the client credentials for a token:
   ```bash
   CLIENT_ID=your_client_id
   CLIENT_SECRET=super_secret
   MAS_BASE=https://mas.example.com

   ACCESS_TOKEN=$(
     curl -s \
       -u "$CLIENT_ID:$CLIENT_SECRET" \
       -d "grant_type=client_credentials&scope=urn:mas:admin" \
       "$MAS_BASE/oauth2/token" | jq -r '.access_token'
   )
   ```
4. Copy the resulting `ACCESS_TOKEN` into `access_token` in `base-config.yaml` (or your deployed config secret).
5. Test the token against the admin API before deploying the bot:
   ```bash
   curl -H "Authorization: Bearer $ACCESS_TOKEN" "$MAS_BASE/api/admin/v1/user-registration-tokens"
   ```

## Release Automation

- Publishing a release (or running the workflow manually) triggers `.forgejo/workflows/build.yml`.
- The workflow runs `./worker build`, renames the archive to `mas-tokenbot-<tag>.mbp`, and uploads it as both a release asset and a workflow artifact.
- Adjust the `runs-on` label in the workflow if your Forgejo runner advertises a different name or does not support the default container image.
