# CLAUDE.md

DKIM + ARC verification for `.eml` files (Gmail Takeout, Outlook/Hotmail web downloads, etc). Single-file tool.

## Run

```
pip install dkimpy dnspython
python verify_dkim_signatures.py [SPEC ...] \
    [--output report.txt] [--key-database keys.json] [--json results.json|-] \
    [--verbose] [--recurse] [--include-fixed] [--attempt-fix]
```

Test corpora live in `ex/` (gitignored).

## Architecture

Single class `DKIMVerifier`:

- **DKIM** — via `OurDKIM(dkim.DKIM)` subclass adding `ignore_exp=True` (don't fail on expired `x=`).
  - **Per-signature index**: a message can carry several `DKIM-Signature` headers (one per signing domain). `our_dkim_verify`/`verify_dkim_with_library` take `idx`; the caller loop must pass each signature's index. Verifying `idx=0` only silently ignores the rest — regression to avoid.
  - **Failure classification** (`_diagnose_dkim_failure`): on any failure, report *why*, not just `False`. Two orthogonal facts drive it: `body_hash_match` (does the body still hash to signed `bh=`? → content intact) and `key_status` (`present`/`revoked`/`absent`, read from the just-populated key DB, no extra DNS). Classes: `KEY_REVOKED` (empty `p=` in DNS = RFC 6376 revocation), `KEY_ABSENT` (no record), `SIGNATURE_INVALID_BODY_INTACT` (body matches but sig fails the current key → almost always the signer rotated keys after signing, or a signed header was altered in transit), `BODY_ALTERED` (body-hash mismatch = real content change). Only `BODY_ALTERED`/error count as extraction-suspicious for the "high failure rate" hint.
  - **Key rotation is the normal cause of old-mail DKIM failure.** Signers rotate/revoke DKIM keys (commonly ~every 6 months); once the signing key leaves DNS, historic mail is permanently unverifiable even though the body is byte-intact. This is expected, not tampering — and it's exactly what ARC is for (the receiving provider froze the original `dkim=pass` verdict into the seal at delivery time, so ARC still passes when live DKIM no longer can).
- **ARC** — via `dkim.arc_verify` directly. Effective status rolled up from raw `cv`:
  - `PASS` — full chain validates
  - `PARTIAL` — all seals valid but body-hash AMS failed → body mutated *after* ARC signing (Microsoft download path)
  - `FAIL` — chain itself broken (a seal failed). Hotmail downloads land here because Microsoft mutates its own ARC headers post-sign on hotmail (outlook.com seals stay valid → PARTIAL there).
  - `NONE` — no ARC headers
- **Key cache** — `key-database.json`, shared DKIM+ARC. Each entry has `roles: ["dkim"|"arc"|both]`. Persistent.
- **File selection** — positional args are specs (file, glob, or directory meaning `DIR/*.eml`), expanded by `expand_specs` and verified by `scan_paths`, which is the single place that counts files and drives the per-file loop. `scan_directory` is now one caller of it, and the old `--single-file` branch in `main` that re-derived `total_files`/`valid_dkim`/`invalid_dkim` by hand is gone -- those counters are incremented in `verify_email_file` and must not be set twice. `--attempt-fix` sidecars are excluded from glob/directory expansion (not from explicitly named files), or a second run counts the tool's own output as new mail. `--replace` deliberately has no short form: `-r` used to mean it, so reusing the letter for `--recurse` would silently change what an old command line does.
- **JSON output** (`--json PATH`, `-` for stdout) — `json_report()` returns `{schema_version, generated, options, stats, results}`, where `results` is the list of per-file dicts `verify_email_file` already builds. It is the *only* structured record of verdicts: the key database is a key cache keyed by domain:selector and stores no verdict (its `status` describes the DNS lookup). Two invariants: (1) a new per-file fact goes in the result dict, not only into report prose, or it exists for humans but not for callers; (2) nothing human-readable may `print()` to stdout from inside the class — it goes to `self.console`, which `main` points at stderr when JSON owns stdout. `JSON_SCHEMA_VERSION` bumps only on a breaking shape change.
- **Console encoding** — `main` reconfigures stdout/stderr to UTF-8 with `errors='replace'`. The report's `✓` recommendation line is unencodable in a legacy console code page, and the resulting encode error aborted an otherwise-finished run from inside the top-level `try` (taking the key-database save and the JSON write with it). Don't remove it.
- **`clean_gmail_export()`** — strips Gmail mbox export headers preceding the real `Delivered-To:`. **CRITICAL: only searches within the message header section (before the first blank line)**. A previous bug searched the whole body and mangled emails whose `message/rfc822` attachments contained `Delivered-To:` in their body. Don't regress this.

## Microsoft fix (`--attempt-fix`, opt-in)

Reverses Exchange Online's body mutations on DKIM-failing emails. Writes `<name>.fixed.eml` alongside original **only when reconstructed body hashes byte-exactly to signed `bh=`** (SHA-256 oracle, no false positives). Never overwrites originals.

Two phases, both under the one flag:

- **Phase 1** — raw-byte strip of `<meta http-equiv="Content-Type" content="text/html; charset=utf-8">` (handles non-QP HTML bodies).
- **Phase 2** — for QP-encoded HTML parts: decode QP → strip meta → optional entity-reversal → re-encode with `quopri.encodestring(data, quotetabs=False)` then CRLF-normalize.

Phase 2 tries variants in order, first `bh=` match wins:
1. `meta-strip only`
2. `+ entity-reverse` — applies `MSOFT_ENTITY_REVERSALS` (currently just `&nbsp;` → `\xc2\xa0`). **Extension point**: add `(entity, raw)` tuples here when new Microsoft entity normalizations are found (em-dash, smart quotes, etc.).
3. `+ safelinks-unwrap` — applies `_SAFELINKS_HREF_RE.sub(rb'href="\1"', html)` to undo Defender Safe Links URL rewrapping (preserves original URL from `originalsrc=`).
4. `+ apostrophe-encode` — `'` → `&#39;` (Microsoft DEcodes the numeric entity).
5. `+ outer-boundary-CRLF-collapse` — body-level regex collapsing `\r\n\r\n--<outer-boundary>` to `\r\n--<outer-boundary>` (Microsoft inserts an empty line before each outer multipart boundary line). Currently scoped to the outermost boundary only.

MIME-boundary detection in `_find_qp_html_part_ranges` collects boundaries from ALL `Content-Type: multipart/*; boundary=` declarations anywhere in the body (not just the body's opening line). This handles nested multipart correctly, including HTML parts inside attached `message/rfc822` files. Don't replace with a regex heuristic; QP content contains byte sequences like `---------- Forwarded message --=` that a heuristic mis-matches.

The body-mutation pipeline recurses naturally into attached `.eml` HTML parts via the boundary scanner — proven on the 5.6MB forwarded-with-3-attached-`.eml`s case where 3 of 4 inner HTML parts decode to byte-exact Gmail truth using the existing variants.

## Empirically established (use these instead of re-investigating)

- **outlook.com and hotmail.com apply identical body mutations** — proven by byte-equality on paired ground-truth send. Reject "hotmail is different" hypotheses for body content.
- **Hotmail does break Microsoft's own ARC-Seal** in the download path (outlook.com doesn't). Header-level only. Can't be fixed from our side; this is what drives hotmail → `FAIL` vs outlook → `PARTIAL` for the same content.
- **Microsoft's known body mutations** (forward direction — what Microsoft does to bytes during their parse/re-serialize cycle):
  - `<meta>` injection in HTML parts — reversed (Phase 1/2)
  - `\xc2\xa0` → `&nbsp;` conversion — reversed (Phase 2 entity-reverse)
  - `&#39;` → `'` apostrophe entity DEcoding — reversed (Phase 2 apostrophe-encode)
  - SafeLinks URL rewrapping with original preserved in `originalsrc=` — reversed (Phase 2 safelinks-unwrap)
  - Empty line inserted before each outer multipart boundary — partially reversed (only outermost boundary)
  - Inside attached `message/rfc822` headers: `Bcc: x` → `BCC: <x>` rewrite, `MIME-Version: 1.0` relocated to just above `Bcc:`/`Content-Type:`, trailing space appended to `Content-Type: message/rfc822;` and `Content-Disposition: attachment;` lines — NOT reversed; needs a header reverser at both outer and per-attached-message levels
  - SafeLinks adds `/` to bare-host URLs (`http://example.com` → `http://example.com/` in `originalsrc=`) — NOT reversed; would need a variant that trims trailing slash from bare-host hrefs after safelinks-unwrap
- **Architectural theory** (not proven but consistent with all observations): Exchange Online stores messages internally as MAPI objects and serializes back to RFC822 on egress. Mutations look like canonical-form re-serialization, not security cleansing. `message/rfc822` attachments are parsed recursively and re-serialized in the same canonical form, which is why their internal headers are mutated. Binary attachments (PDF, docx, MP4, JPEG) appear to pass through largely untouched — the MP4 in the test corpus shows only a 1-byte trailing-CRLF difference. This is inference, not proof; falsify by paired-send with PDF/docx attachments if it matters.
- **Python's `quopri.encodestring(data, quotetabs=False)` + CRLF normalization is byte-exact to Gmail's encoder** (verified on ~9KB roundtrip, both consumer @gmail.com and Workspace `gappssmtp.com` signers).

## To gather data for new mutation reversals

Need paired ground truth. Compose one email with QP-triggering content (a paragraph of prose, or an emoji/em-dash) and send in a single message to: an @gmail.com (ground truth), an outlook.com, a hotmail.com. Download all three `.eml`s. Byte-diff each Microsoft copy against the Gmail copy to characterize the mutation set.
