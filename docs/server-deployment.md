# Server deployment

For whoever runs `eyesonly-server` for a team: install, TLS, systemd, backups and upgrades.

The server is one Node process. It authenticates users, hides refs per user, and runs the
pre-receive hook that enforces the policy. It has no database. All state lives in one
directory (`EYESONLY_DATA`).

## Requirements

- Node >= 22
- git >= 2.40 on the server. Older git can still serve repos, but pushes that touch a
  `.gitattributes` or `.lfsconfig` file are refused with
  `server git too old for attribute checks (need >= 2.40)`.
- A TLS-terminating reverse proxy (Caddy, nginx, a load balancer). The server speaks plain
  HTTP and uses HTTP Basic auth, so tokens cross the wire on every request.

SSH transport, a web UI and SSO are not supported.

## Install

### npm

```bash
npm i -g eyesonly            # installs eyesonly, git-eyesonly and eyesonly-server
eyesonly-server              # prints usage
```

### Docker

```bash
docker build -t eyesonly .
docker run -d --name eyesonly -p 127.0.0.1:8787:8787 -v eyesonly-data:/data eyesonly
```

Notes:

- The image is `node:24-alpine` plus git. It runs as an unprivileged `eyesonly` user with
  `EYESONLY_DATA=/data`.
- Inside the container the server listens on `0.0.0.0:8787`. Publish it on
  `127.0.0.1` (as above) and put your TLS proxy in front.
- Run admin commands with `docker exec`. They run as the same user and data dir:

```bash
docker exec -it eyesonly eyesonly-server user add eyesonlypub1:...
docker exec -it eyesonly eyesonly-server repo create app.git --admin alice
```

## Data directory

`EYESONLY_DATA` defaults to `./eyesonly-data` relative to the current directory, so always
set it explicitly. Every admin command must use the same value as the running server.

```
$EYESONLY_DATA/
  users.json                         users, public keys, SHA-256 token hashes (mode 0600)
  repos/
    app.git/                         a normal bare repo
      eyesonly.json                  the policy (see policy-reference.md)
      eyesonly-attestation.json      admin-signed policy manifest, if you use signing
      hooks/pre-receive              the enforcement hook (written by `repo create`)
      eyesonly-mirror.json           mirror config, if set (mode 0600)
      eyesonly-mirror.log            mirror history
      eyesonly-mirror-stage.git/     mirror staging repo
```

## First run

```bash
export EYESONLY_DATA=/srv/eyesonly
eyesonly-server user add eyesonlypub1:...          # the admin's public card; prints a token once
eyesonly-server repo create app.git --admin alice  # the admin must already be a user
eyesonly-server policy set app.git policy.json     # or `-` to read stdin
eyesonly-server serve --host 127.0.0.1 --port 8787
```

A new repo's policy is `{ "members": ["*"], "admins": ["<admin>"] }` with no protected
files or branches. See [policy-reference.md](policy-reference.md) for the full format.
Each developer creates their key with `eyesonly keygen <name>`, which prints the public card
you pass to `user add`.

## Binding

`serve` listens on `127.0.0.1:8787` by default. Flags:

- `--host <addr>`: interface to bind. Keep it on loopback behind a proxy.
- `--port <n>`: port. `0` picks a free one. Without `--port`, the server uses the `PORT`
  environment variable, then 8787.

The server serves the landing page at `/` and returns `ok` at `/healthz`.

## TLS with Caddy

Caddy streams request and response bodies by default, which is what git needs.

```caddyfile
git.example.com {
	reverse_proxy 127.0.0.1:8787
}
```

## TLS with nginx

Git pushes can be large and slow. Don't buffer them, and don't cap their size.

```nginx
server {
    listen 443 ssl;
    server_name git.example.com;
    ssl_certificate     /etc/letsencrypt/live/git.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/git.example.com/privkey.pem;

    client_max_body_size 0;          # pushes have no size limit at the proxy
    proxy_request_buffering off;     # stream pushes to the server
    proxy_buffering off;             # stream packs back to clients
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
    }
}
```

The server reads the `Authorization`, `Content-Type`, `Content-Length` and
`Content-Encoding` headers, which nginx forwards by default. It doesn't read
`X-Forwarded-*`.

### Rate limiting

The server has no rate limiting or request timeouts of its own. Tokens are 192-bit random
values, so guessing isn't practical, but limiting requests per IP at the proxy is cheap:

```nginx
# in http { }
limit_req_zone $binary_remote_addr zone=git:10m rate=20r/s;
# in location / { }
limit_req zone=git burst=100 nodelay;
```

## systemd

```ini
# /etc/systemd/system/eyesonly.service
[Unit]
Description=Eyes Only git server
After=network.target

[Service]
User=eyesonly
Group=eyesonly
Environment=EYESONLY_DATA=/srv/eyesonly
Environment=HOME=/srv/eyesonly
ExecStart=/usr/bin/eyesonly-server serve --host 127.0.0.1 --port 8787
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/srv/eyesonly

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd --system --home /srv/eyesonly --create-home eyesonly
sudo systemctl enable --now eyesonly
```

Use `command -v eyesonly-server` to find the right `ExecStart` path. Run admin commands as
the service user, with the same data dir:

```bash
sudo -u eyesonly EYESONLY_DATA=/srv/eyesonly eyesonly-server repo list
```

## Environment variables

| Variable | Read by | Meaning |
|---|---|---|
| `EYESONLY_DATA` | server, admin CLI, mirror | Data directory. Default `./eyesonly-data` |
| `PORT` | `serve` | Port when `--port` isn't given. Default 8787 |
| `EYESONLY_MAX_UPLOAD_PACK_BODY` | `serve` | Cap on a fetch negotiation request, in bytes (default 10 MiB). Larger requests get HTTP 413. Pushes aren't capped |
| `EYESONLY_ALLOW_PROTOCOL_V2` | `serve` | Set to `1` to pass the client's `Git-Protocol` header through. **Don't.** Protocol v2 lets a client fetch hidden objects by SHA, which breaks private branches. It exists for tests |
| `HOME`, `PATH` | `serve`, mirror | Passed to `git http-backend` and the mirror's git. `git` must be on `PATH` |

`EYESONLY_USER` is set by the server for the pre-receive hook. Don't set it yourself.

## Backups

Back up all of `EYESONLY_DATA`. Taking a filesystem snapshot, or stopping the service while
you copy, avoids catching a push halfway through.

- `users.json` holds public keys and SHA-256 hashes of tokens, never the tokens themselves.
  A leaked backup doesn't hand out working tokens. It does reveal user names and public keys.
- The server never holds private keys or the plaintext of protected files. Protected files
  are stored as ciphertext in the repos.
- If you lose `users.json`, re-add each user from their public card (`user add`). The same
  card means the same keys, so existing ciphertext stays readable. Everyone gets a new token.
- The mirror credential file lives outside the data dir (see the README). Back it up
  separately, or reissue it.

## Upgrades

```bash
npm i -g eyesonly@latest      # or rebuild the Docker image
sudo systemctl restart eyesonly
```

`repo create` writes `hooks/pre-receive` with the **absolute paths** of the Node binary and
`eyesonly-server.mjs` that ran it. If either path changes (a new Node version under nvm, a
different npm prefix), pushes to existing repos fail, closed. Check one:

```bash
cat "$EYESONLY_DATA/repos/app.git/hooks/pre-receive"
```

Rewrite it with the current paths:

```bash
NODE="$(command -v node)"
CLI="$(npm root -g)/eyesonly/bin/eyesonly-server.mjs"
for d in "$EYESONLY_DATA"/repos/*.git; do
  printf "#!/bin/sh\nexec '%s' '%s' hook pre-receive\n" "$NODE" "$CLI" > "$d/hooks/pre-receive"
  chmod 755 "$d/hooks/pre-receive"
done
```

In the Docker image the paths are fixed (`/usr/local/bin/node`, `/app/bin/...`), so
rebuilding is enough.

## Health check

```bash
curl -fsS http://127.0.0.1:8787/healthz     # prints ok
```

The Docker image runs this check on its own.

## Next

- [policy-reference.md](policy-reference.md): who can read, write and see what
- [team-workflows.md](team-workflows.md): adding people, offboarding, private branches
- [ci.md](ci.md): giving CI access to secrets
- [existing-repos.md](existing-repos.md): moving an existing repo onto the server
- [troubleshooting.md](troubleshooting.md)
