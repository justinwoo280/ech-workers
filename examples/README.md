# EWP v2 — example configurations

All configs in this directory drive the unified `cmd/ewp` binary:

```
ewp -config <file>.yaml
```

| File | Role |
|---|---|
| `client-socks5.yaml` | Local SOCKS5 proxy → ewpclient (WebSocket+ECH+ML-KEM) |
| `client-http.yaml` | Local HTTP CONNECT proxy → ewpclient |
| `client-tun.yaml` | OS-level TUN interface (TODO: still needs platform setup) |
| `server.yaml` | EWP-WebSocket listener + direct outbound (typical VPS deployment) |
| `relay.yaml` | EWP listener + ewpclient outbound (chain through another node) |

Replace placeholder values (`UUID`, `URL`, certificate paths) before running.

## UUID

Generate with `uuidgen` or any UUID v4 tool. The same UUID must be present on
both client (in `outbounds[].uuid`) and server (in `inbounds[].uuids`).

## TLS

Server-side TLS uses standard PEM cert/key. Get them from Let's Encrypt
(`certbot`) or any other CA. Client-side TLS uses the embedded Mozilla CA
bundle by default; no system trust store dependency.

## ECH

To enable ECH, point `ech: true` and ensure your server's domain has an
HTTPS resource record advertising the ECH config. The bootstrap DoH (in the
`ech.bootstrap_doh` block) fetches that record at startup.

## TUN routing-loop guard

`client-tun.yaml` MUST set `inbounds[].bypass_server` to the upstream EWP
server's host:port. Without it the bypass dialer cannot identify the
physical outbound interface and the ewpclient outbound's own packets will
loop back through the TUN — total connectivity loss.

## NAT diagnostics

The server side automatically discovers its public reflexive address at
startup if you set the `stun:` block (see `server.yaml`). Clients can ask
"what NAT am I behind?" with a one-shot probe:

```
ewp -config client-socks5.yaml \
    -probe-nat stun.cloudflare.com:3478
```

This sends one `UDP_PROBE_REQ` through the default ewpclient outbound and
prints the reflexive address the server saw, then exits.

## What's gone from v1

If you're migrating an existing config, drop these — they're either no-ops
in v2 or have been replaced:

- `appProtocol: trojan` / `protocol: trojan` — Trojan support removed.
- `flow: xtls-rprx-vision`, `enableFlow: true` — flow padding superseded
  by the v2 outer transport's framing.
- `xhttpMode: stream-down` — only `stream-one` is implemented (RPRX
  himself recommends against `stream-down`).
- `tunnel-doh-server` — DNS no longer rides the tunnel as its own flow.
