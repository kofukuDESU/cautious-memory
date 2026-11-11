# Proxy Pipeline

Automated proxy-config collector, tester, and labeler. Fetches subscription links,
tests every node through a real **Xray-core** session, and annotates the survivors
with exit country and Gemini availability. Built to run unattended on **GitHub
Actions** and commit fresh lists back to the repo.

---

## How it works

```
sub_links.txt ──► [1] Fetch + normalize + dedupe ──► ALIVE/all.txt
                          │
                  [2] Endpoint test (xray + HTTPS probes) ──► ALIVE/working.txt
                          │
                  [3] Enrich (Gemini + Geo) ──► ALIVE/enriched.txt
```

- Every config gets its **own isolated xray process** (local SOCKS5 inbound, `socks5h`
  remote DNS — no local DNS leaks).
- When steps **2+3** run together, they share **one xray session per config**.
- A node is *alive* if **any** probe returns its expected response
  (`204` from Cloudflare/gstatic `generate_204`, or Apple's `Success` page),
  with one full retry round and realistic `(3s, 5s)` timeouts.
- Results are written incrementally — a crashed or time-budgeted run still leaves
  usable partial lists.

## Output labels

`ALIVE/enriched.txt` contains the same share links with rewritten remarks:

```
🇩🇪-DE-GEMINI-042
🇳🇱-NL-NOGEMINI-107
🇺🇸-US-GEMERR-013
DEAD-055
```

| Part | Meaning |
|---|---|
| `🇩🇪-DE` | Exit country (flag + ISO code). Omitted if geo lookup failed. |
| `GEMINI` | Tested: Gemini loaded with no geo-block detected. |
| `NOGEMINI` | Tested: Gemini's "not supported in your country" page detected. |
| `GEMERR` | **Inconclusive** — timeout, captcha/consent wall, HTTP error. *Not* the same as blocked. |
| `DEAD` | The proxy itself failed the liveness probe (only appears in enrich-only runs). |
| `-042` | Per-run index so identical results still get unique names. |

> `GEMINI` refers to the **web app** (gemini.google.com), not the API / AI Studio.

## Supported protocols

| Supported | Skipped (counted + logged) |
|---|---|
| `vmess` (JSON variants, URL-safe base64) | `hysteria` / `hysteria2`, `tuic` (need sing-box) |
| `vless` (ws / grpc / h2 / tcp / httpupgrade / xhttp, TLS + REALITY) | `wireguard`, `ssr` |
| `trojan` (TLS implied when `security` is omitted) | `ss` with SIP003 plugins (`obfs`, `v2ray-plugin`) |
| `shadowsocks` (SIP002, legacy base64, plaintext userinfo) | `kcp` / `quic` transports, REALITY without `pbk` |

Subscriptions may be plain text, base64 (standard or URL-safe, up to 3 layers),
or mixed line-by-line — all are normalized before extraction.

## Requirements

- Python **3.10+**
- `pip install "requests[socks]"`
- **xray** binary — auto-downloaded into `./bin/` if missing (disable with
  `--no-install-xray`, pin with `XRAY_VERSION=v26.11.9`, or set `XRAY_BINARY`).

## Quick start (local)

```bash
pip install "requests[socks]"

# one subscription URL per line; '#' comments allowed
nano sub_links.txt

python proxy_pipeline.py                  # interactive menu (TTY only)
python proxy_pipeline.py --steps 1+2+3    # non-interactive
python proxy_pipeline.py --steps 1+2 --custom-file my_nodes.txt
```

## CLI reference

| Flag | Default | Description |
|---|---|---|
| `--steps` | prompt / `1+2+3` in CI | Step combo: `1`, `1+2`, `1+2+3`, `1+3`. Step 1 is always required. |
| `--custom-file PATH` | — | Use a local config file as the source instead of fetching. |
| `--workers N` | `20` | Concurrent test workers (each ≈ one xray process, ~35 MB RAM). |
| `--time-budget MIN` | `0` (unlimited) | Stop testing gracefully after N minutes; partial results are still saved. |
| `--fetch-proxy URL` | — | Proxy for fetching subscriptions / downloading xray, e.g. `socks5h://127.0.0.1:1080`. |
| `--allow-insecure` | off | Honor `allowInsecure=1` links (self-signed certs). Off by default — enabling it makes those tests MITM-able. |
| `--no-install-xray` | off | Fail instead of auto-downloading xray when it's missing. |

### Environment variables

| Variable | Purpose |
|---|---|
| `PROXY_STEPS` | Default for `--steps` (handy for scheduled CI runs). |
| `FETCH_PROXY` | Default for `--fetch-proxy` (store as a CI secret). |
| `XRAY_BINARY` | Path/name of an existing xray binary. |
| `XRAY_VERSION` | Pin the auto-installed release, e.g. `v26.11.9`. Default: latest. |
| `GITHUB_ACTIONS` / `CI` | Auto-detected: disables prompts, defaults steps to `1+2+3`. |
| `GITHUB_STEP_SUMMARY` | Auto-detected: a results table is appended to the job summary. |

**Exit codes:** `0` success · `1` error or empty source · `130` interrupted / stopped early.

## GitHub Actions setup

1. Commit `proxy_pipeline.py`, `sub_links.txt`, and the workflow below.
2. Add `bin/` to `.gitignore` (the auto-installed xray binary shouldn't be committed).
3. The workflow needs `contents: write` (already declared below).
4. Runs every 6 hours, or manually via **Actions → proxy-pipeline → Run workflow**.

`.github/workflows/proxy.yml`:

```yaml
name: proxy-pipeline

on:
  schedule:
    - cron: "0 */6 * * *"        # every 6 hours (UTC)
  workflow_dispatch:
    inputs:
      steps:
        description: "Steps (1 / 1+2 / 1+2+3)"
        default: "1+2+3"

permissions:
  contents: write

concurrency:
  group: proxy-pipeline
  cancel-in-progress: false

jobs:
  run:
    runs-on: ubuntu-latest
    timeout-minutes: 90
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: python -m pip install "requests[socks]"

      - name: Run pipeline
        run: |
          python proxy_pipeline.py \
            --steps "${{ github.event.inputs.steps || '1+2+3' }}" \
            --time-budget 75

      - name: Upload diagnostics
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: pipeline-logs
          path: logs/
          retention-days: 7

      - name: Commit results
        if: always()
        run: |
          git config user.name  "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add ALIVE logs/summary.json
          git diff --cached --quiet || git commit -m "chore: update proxy lists [skip ci]"
          git push
```

**Safety pair:** `--time-budget 75` + `timeout-minutes: 90`. The script stops testing
at 75 minutes, flushes everything, and the commit step still runs — partial results
beat no results. If all subscription fetches fail, the script exits non-zero
**without overwriting** your previous lists.

## Using the lists

Import `ALIVE/enriched.txt` into any client that accepts raw share links
(v2rayN, NekoBox, …), or point the client's subscription field at the file's
**raw GitHub URL** — plain-text URI lists work as subscriptions in most clients.
Filter by remark: keep `GEMINI`, treat `GEMERR` as "untested", avoid `NOGEMINI`.

## Project layout & logs

```
.
├── proxy_pipeline.py
├── sub_links.txt              # your subscription URLs
├── .github/workflows/proxy.yml
├── ALIVE/
│   ├── all.txt                # deduplicated source configs
│   ├── working.txt            # configs that passed the endpoint test
│   └── enriched.txt           # annotated configs
├── logs/
│   ├── summary.json           # machine-readable run summary (committed)
│   ├── enrich_checks.txt      # per-node Gemini status + response excerpts
│   ├── failed.txt             # subscription URLs that failed to fetch
│   └── fatal.txt              # traceback, if the run crashed
└── bin/                       # auto-installed xray (gitignored)
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `SOCKS proxy support is missing` | `pip install "requests[socks]"` |
| xray download fails | Set `XRAY_BINARY`, or `FETCH_PROXY` if GitHub is unreachable from your network. |
| Everything is `GEMERR` | Read `logs/enrich_checks.txt` — likely captcha walls (datacenter IPs) or Google changed the page. |
| Subscriptions fail on CI but work locally | Provider blocks datacenter IPs → set a `FETCH_PROXY` secret. |
| Job hits its timeout | Lower `--time-budget`, or raise `timeout-minutes`. |
| Lists unchanged after a run | Check `logs/failed.txt` — an empty source never overwrites previous outputs. |

## Accuracy notes & limitations

- **Gemini detection is a heuristic** (English forced via `?hl=en`, HTML/JSON-escaped
  apostrophes handled, consent/captcha pages classified as `GEMERR`). Audit
  `logs/enrich_checks.txt` after the first run to confirm the block marker appears
  in served pages.
- **Geo** comes from Cloudflare's `/cdn-cgi/trace` over HTTPS (`loc=`), with
  ip-api.com as fallback (HTTP-only, 45 req/min per IP).
- **Deduplication** uses the full functional fingerprint (address, port, credentials,
  transport, TLS parameters) — remarks are ignored, so rebranded duplicates collapse.
- Free public nodes churn constantly; every list is a snapshot, not a guarantee.
- `GEMERR` means *unknown*, not *blocked* — don't discard those nodes blindly.

## Disclaimer

For testing your own proxies and lawful personal use. Respect your providers'
terms of service and applicable local laws. No warranty — the lists are provided
as-is.
