# Deploy with Docker Compose

Eyes Only behind [Caddy](https://caddyserver.com), which gets and renews a Let's Encrypt
certificate on its own. You need a host with Docker, a domain pointing at it, and ports 80
and 443 open.

```bash
git clone https://github.com/jagritvats/eyesonly && cd eyesonly/deploy
echo "EYESONLY_DOMAIN=code.example.com" > .env     # your domain
docker compose up -d
```

Create the admin and the first repo. On your laptop, `eyesonly keygen <you>` prints your
public card; then on the server:

```bash
docker compose run --rm eyesonly eyesonly-server init \
  --admin eyesonlypub1:... --repo app.git --url https://code.example.com
```

`init` prints your token once and the exact clone or push commands to run next. It refuses
to run over an existing user or repo.

Day-to-day admin commands run the same way:

```bash
docker compose run --rm eyesonly eyesonly-server user add eyesonlypub1:...
docker compose run --rm eyesonly eyesonly-server policy show app.git
docker compose exec eyesonly eyesonly-server mirror push app.git   # in the running container
```

What's where:

| | |
|---|---|
| `docker-compose.yml` | `eyesonly` (built from the repo's Dockerfile, not published on the host) and `caddy` (ports 80/443) |
| `Caddyfile` | TLS for `$EYESONLY_DOMAIN`, streaming in both directions, 1 h timeouts, no body size limit |
| volume `eyesonly-data` | users (token hashes), repos and policies. **Back this up.** |
| volumes `caddy-data`, `caddy-config` | certificates |

Upgrade: `git pull && docker compose build && docker compose up -d`.

More: [docs/server-deployment.md](../docs/server-deployment.md).
