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

## Release Automation

- Pushing a tag that matches `v*` triggers `.forgejo/workflows/build.yml`.
- The workflow runs the same `./worker build` helper and publishes the `.mbp` as a build artifact.
- Adjust the `runs-on` label in the workflow if your Forgejo runner advertises a different name.
