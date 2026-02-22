# Self-Proxy

A proxy for **Nexus** that enables **package whitelisting**. Only whitelisted packages can be downloaded; metadata is proxied transparently. Designed to sit in front of Nexus so that package managers (npm, etc.) resolve metadata through the proxy while tarball/artifact downloads are allowed only for explicitly whitelisted packages.

## Supported package formats

| Format    | Status   |
|----------|----------|
| **npm**  | Supported |
| Maven    | Planned  |
| NuGet    | Planned  |
| R        | Planned  |
| Python   | Planned  |
| Container| Planned  |

## How it works

1. **Metadata** (e.g. npm package manifest) is proxied from the upstream registry (e.g. `registry.npmjs.org`) and returned to the client. Tarball URLs in the response are rewritten to point at the proxy.
2. **Tarball/artifact download** is allowed only if the package is on the **whitelist**. If not whitelisted, the proxy returns `403 Forbidden`.
3. After a whitelisted package’s tarball is streamed through the proxy, that package is removed from the whitelist so that subsequent requests go to Nexus (which has cached the artifact).

Typical flow: configure Nexus to use this proxy as an upstream, whitelist the packages you need (e.g. from `package-lock.json`), then run `npm install`; the proxy serves only the whitelisted packages and Nexus caches them.

## Requirements

- Python 3.12+
- [FastAPI](https://fastapi.tiangolo.com/) and [httpx](https://www.python-httpx.org/)

## Quick start

```bash
# From the project root
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API is available at `http://localhost:8000`. OpenAPI docs: `http://localhost:8000/docs`.

## Protecting the proxy API (Bearer token)

To require authentication so only Nexus (or other trusted callers) can use the proxy, set a Bearer token via **env** or **file**:

- **Env:** set `PROXY_BEARER_TOKEN` to the secret token.
- **File:** set `PROXY_BEARER_TOKEN_FILE` to the path of a file whose first line is the token (e.g. avoid storing the token in process list or env dumps).

Env takes precedence. If neither is set, the API is open (no auth).

Clients must send: `Authorization: Bearer <token>` on every request. Invalid or missing token returns `401 Unauthorized`.

Example with env:

```bash
export PROXY_BEARER_TOKEN=your-secret-token
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Example with file:

```bash
echo -n "your-secret-token" > .proxy-bearer-token
export PROXY_BEARER_TOKEN_FILE=.proxy-bearer-token
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Configure Nexus (or your client) to send this token when calling the proxy.

## npm usage

### Base URL

All npm proxy routes are under `/npm`.

### Whitelist a package

Before a package’s tarball can be downloaded, it must be whitelisted via **PATCH**:

- Unscoped: `PATCH /npm/{package_name}`
- Scoped:   `PATCH /npm/@{scope}/{package_name}`

Example:

```bash
# Unscoped package
curl -X PATCH http://localhost:8000/npm/lodash

# Scoped package
curl -X PATCH http://localhost:8000/npm/@babel/core
```

### Whitelist from package-lock.json

Use the script in `tests/npm/` to whitelist every package in a lockfile:

```bash
./tests/npm/whitelist-all.bash path/to/package-lock.json
```

### Point npm at Nexus (Nexus uses the proxy)

Configure npm to use your Nexus repository (Nexus is configured to use this proxy as its upstream). Example `.npmrc`:

```
registry=http://localhost:8081/repository/npmjs/
```

Then run `npm install` as usual; only whitelisted packages will be downloadable through the proxy.

## Project layout

```
app/
  main.py           # FastAPI app, mounts routers
  config.py         # Proxy config (e.g. Bearer token from env/file)
  auth.py           # Bearer token dependency to protect the API
  routers/
    npm.py          # npm registry proxy + whitelist
tests/
  npm/              # Scripts and config for testing npm (whitelist, .npmrc)
```

## License

See repository for license information.
