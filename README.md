# Proxy pipeline

Fetches proxy subscriptions from `sub_links.txt`, verifies reachability,
and enriches each alive config with Gemini availability, country, and
residency classification. Runs every 24h via GitHub Actions.

## Pipeline

1. **Fetch** — pull every URL in `sub_links.txt`, extract, dedupe.
2. **Endpoint Test** — probe Cloudflare / gstatic / Apple captive portal.
3. **Enrich** — per config, check Gemini, geolocate, classify residency.
   Original remarks are discarded.

## Outputs

All files are plain text (one URI per line), committed by the workflow:

| File | Contents |
|---|---|
| `ALIVE/all.txt`       | deduplicated source configs |
| `ALIVE/working.txt`   | configs that passed the endpoint test |
| `ALIVE/enriched.txt`  | every working config annotated with `<flag>-<CC>-<GEMINI\|NOGEMINI>-<RESIDENTIAL\|HOSTING\|VPN>` |

Example enriched remark: `🇩🇪-DE-GEMINI-RESIDENTIAL`

## Local use

```bash
pip install requests proxy-ip-check
# xray on PATH — https://github.com/XTLS/Xray-core/releases

python3 deepseek_python_simpled.py                      # interactive
python3 deepseek_python_simpled.py --steps '1+2+3'      # headless, all steps
python3 deepseek_python_simpled.py --steps '1+2+3' --custom-file mylist.txt

This readme was written by DEEPSEEK v4.1 Flash.
