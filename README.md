# verify_dkim_signatures.py

A single-file Python CLI that verifies DKIM and ARC signatures on `.eml` files — typically ones you've downloaded from a web mail service like Gmail, Outlook.com, or Hotmail (both providers support saving an individual email to an `.eml` file from their web UI; Gmail also supports bulk export via Takeout). Beyond the core verification, it also provides:

- A **persistent local cache** of DKIM/ARC public keys, so you can verify archived emails even after a sender rotates or revokes their keys — and even fully offline.
- An opt-in **fix mode** that makes a best-effort to reverse body changes Outlook.com and Hotmail apply during delivery, so the original DKIM signature verifies again on a downloaded `.eml` file.

## Heads-up: this was vibe-coded

I built this iteratively with Claude over many sessions, testing each feature against real `.eml` files I sent to myself across Gmail, Outlook.com, and Hotmail. It works, it's been tested on real-world emails, but it isn't structured the way I'd write a production library from scratch.

A specific caveat about the Outlook.com / Hotmail fix mode: those services modify incoming emails before they reach your mailbox, so the `.eml` files you download from them won't pass DKIM verification unless those modifications are reversed first. This script knows how to reverse the specific modifications observed during my limited testing. If your downloaded `.eml` files contain a modification this script hasn't seen before, your mileage may vary — you may need to vibe-code your own fixes into place.

Sharing as-is in case it's useful to someone. It's a small thing I threw together for my own archives; there may well be more comprehensive tools out there that solve this more thoroughly.

## What this tool does

For each `.eml` file you point it at, the tool:

1. Reads the email's `DKIM-Signature` header.
2. Downloads the sender's public DKIM key from DNS and stores it in a local `key-database.json` file so it doesn't need to be re-fetched next time. (You can also verify against cached keys with no DNS at all — useful for archived emails whose sender has since rotated or revoked the key.)
3. Runs the cryptographic check that confirms the email really was sent by the domain it claims, and that the body wasn't altered after signing.

It also verifies ARC chains (a related signature mechanism used by forwarding intermediaries) when those headers are present.

This works straightforwardly for Gmail `.eml` downloads — whether saved one-at-a-time from the web UI or bulk-exported via Takeout, Gmail preserves the exact bytes that were originally signed.

### The Outlook.com / Hotmail wrinkle

The `.eml` files you download from Outlook.com and Hotmail.com have already been modified by the service during delivery — a `<meta>` tag is injected in HTML parts, some characters are swapped for HTML entities, URLs are rewrapped with Defender SafeLinks, and so on. Most of these look like incidental byproducts of how the service parses messages internally and re-emits them on download; SafeLinks is the one that's a deliberate security feature. The original DKIM signature still travels with the email but no longer matches the modified body, so standard verifiers report "invalid" even though the content is the same.

The opt-in fix mode (`--attempt-fix`) tries to reverse every modification this script has been taught to recognize, then re-checks the signature. When the reconstructed body **cryptographically** matches what the sender originally signed, the fixed bytes are written to a sidecar named `<name>.fixed.eml` next to the original (or, with `--replace`, the original `.eml` is overwritten in place). The match must be byte-exact, so there's no scenario where a wrong file is written. The modifications currently handled cover every case observed during testing, but the service may mutate emails in other ways this script hasn't seen — in which case fix mode will simply not produce a `.fixed.eml` for that email, and you'd need to vibe-code the missing reversal yourself.

## Requirements

- Python 3
- `pip install dkimpy dnspython`

## Quick start

```
# Verify a directory of .eml files (uses DNS for keys, caches them locally):
python verify_dkim_signatures.py ./emails/

# One file with full detail and a saved report:
python verify_dkim_signatures.py --single-file foo.eml --output report.txt ./emails/

# Reverse known mutations on Outlook.com / Hotmail downloads so signatures verify again:
python verify_dkim_signatures.py --attempt-fix ./emails/

# Verify against your cached keys only — no DNS at all (good for archived emails):
python verify_dkim_signatures.py --offline-only ./emails/
```

## CLI

| Flag | Purpose |
|------|---------|
| `<directory>` | directory of `.eml` files to scan |
| `--verbose`, `-v` | per-email detail in console output |
| `--output PATH`, `-o PATH` | also write the report to a UTF-8 file (implies detail) |
| `--key-database PATH` | persistent key cache (always on; defaults to `./key-database.json`) |
| `--single-file FILE` | verify one file instead of scanning a directory |
| `--attempt-fix` | reverse known body mutations on Outlook.com / Hotmail downloads; writes `<name>.fixed.eml` when reconstruction matches the signed hash |
| `--replace`, `-r` | with `--attempt-fix`: overwrite the original `.eml` in place (destructive) |
| `--offline-only` | never query DNS; verify against cached keys only |
| `--overwrite-keys` | allow DNS to refresh cached keys (off by default — cached keys are kept forever) |

## The key cache

Every DKIM/ARC public key the tool fetches from DNS is saved to `key-database.json`. By default, once a key is cached it is **never overwritten** — this matters for archived emails, where the sender's DNS record may eventually disappear (selector rotation, domain expiration, key revocation). The cached key is then your only way to verify the signature.

On each save the previous file is rotated to `key-database.json.bak`.

Use `--overwrite-keys` to opt in to refreshing cached keys from DNS.

## Mutations currently reversed by `--attempt-fix`

For reference, these are the specific body changes the fix mode knows how to reverse on Outlook.com / Hotmail downloads:

- Injected `<meta http-equiv="Content-Type" …>` tags in HTML parts
- `&nbsp;` ↔ raw non-breaking space substitution
- `&#39;` ↔ `'` apostrophe substitution
- Defender SafeLinks URL rewrapping (using the `originalsrc=` that SafeLinks itself preserves)
- Trailing-slash added to bare-host URLs by SafeLinks
- Blank line inserted before each `multipart/mixed` boundary
- Trailing space stripped from certain attached-message header lines
- `Bcc:` header reformatting inside attached `.eml` parts
- `MIME-Version:` repositioning inside attached `.eml` parts

## License

MIT — see [LICENSE](LICENSE).
