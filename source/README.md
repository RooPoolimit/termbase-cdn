# Termbase CDN Source Snapshot

This directory is a generated snapshot from the backend termbase project. Do not edit files here directly.

When backend data or compiler code changes, run the backend script again:

```powershell
python sync_to_cdn.py --cdn-path D:\Gloss-translator\termbase-cdn
```

Then review the CDN repo diff and commit manually.

Files:

- `compiled_schema.py`: runtime compiled payload contract constants
- `termbase_signing.py`: Ed25519 canonical-message + verify helpers (signature check in publish_from_source.py)
- `PUBKEYS.json`: signature trust list (authoritative copy lives in the backend repo; hashed in SOURCE_VERSION)
- `termbase_compiler.py`: CDN-side compiler copy, patched to read `termbase.published.db`
- `publish_from_source.py`: GitHub Action helper for dry-run/apply publishing
- `termbase.published.db`: minimal approved runtime database
- `requirements.txt`: Python dependencies for GitHub Actions
- `SOURCE_VERSION.txt`: backend snapshot hashes
