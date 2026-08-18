import base64
import json
import os
import shutil
import sqlite3
import tempfile
import unittest

import publish_from_source
import termbase_signing as ts


def write_runtime_db(path):
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE terms (
            id INTEGER PRIMARY KEY,
            source_term TEXT NOT NULL,
            target_term TEXT NOT NULL,
            source_lang TEXT NOT NULL DEFAULT 'en-US',
            target_lang TEXT NOT NULL DEFAULT 'zh-CN',
            preferred_translation TEXT DEFAULT '',
            keep_english_v2 TEXT DEFAULT 'never',
            domain_tags TEXT DEFAULT '[]',
            status TEXT DEFAULT 'approved'
        );
        CREATE TABLE term_aliases (
            id INTEGER PRIMARY KEY,
            term_id INTEGER NOT NULL,
            alias TEXT NOT NULL
        );
        CREATE TABLE term_wrong_translations (
            id INTEGER PRIMARY KEY,
            term_id INTEGER NOT NULL,
            wrong_translation TEXT NOT NULL,
            severity TEXT DEFAULT 'medium'
        );
        CREATE TABLE term_contexts (
            id INTEGER PRIMARY KEY,
            term_id INTEGER NOT NULL,
            context_type TEXT NOT NULL,
            definition_zh TEXT DEFAULT ''
        );
        CREATE TABLE term_relations (
            id INTEGER PRIMARY KEY,
            term_id INTEGER NOT NULL,
            related_term_text TEXT NOT NULL,
            relation_type TEXT NOT NULL,
            relation_weight REAL DEFAULT 0.5
        );
    """)
    conn.executemany("""
        INSERT INTO terms (
            id, source_term, target_term, source_lang, target_lang,
            preferred_translation, keep_english_v2, domain_tags, status
        ) VALUES (?, ?, ?, 'en-US', 'zh-CN', '', 'never', '["ai_ml"]', 'approved')
    """, [
        (1, "Agent", "智能体"),
        (2, "RAG", "检索增强生成"),
    ])
    conn.commit()
    conn.close()


def copy_source_tree(target):
    source_dir = os.path.dirname(os.path.abspath(__file__))
    for name in ["compiled_schema.py", "termbase_compiler.py", "termbase_signing.py",
                 "runtime_contract.py", "publish_from_source.py"]:
        shutil.copy2(os.path.join(source_dir, name), os.path.join(target, name))
    with open(os.path.join(target, "runtime_contract.json"), "w", encoding="utf-8") as f:
        json.dump({"schema_version": 1, "required_surfaces": []}, f)
    write_runtime_db(os.path.join(target, "termbase.published.db"))
    hashes = {
        name: publish_from_source.sha256_file(os.path.join(target, name))
        for name in ["compiled_schema.py", "termbase_compiler.py", "termbase_signing.py",
                     "termbase.published.db"]
    }
    with open(os.path.join(target, "SOURCE_VERSION.txt"), "w", encoding="utf-8") as f:
        f.write("backend_commit: test\n")
        f.write("copied_at: 2026-05-31T00:00:00Z\n")
        f.write("files:\n")
        for name in sorted(hashes):
            f.write(f"  {name}: {hashes[name]}\n")


def _sign_source(source, *, key_id="k1", publish_seq=1, trusted_ids=None, mutate=None):
    """Compile the source DB, sign the compiled bytes, and write source/PUBKEYS.json
    + source/SIGNATURE — mirrors the offline signer (sign_compiled.py). `mutate(record)`
    may tamper the record before it is written; `trusted_ids` lets PUBKEYS carry extra
    key ids (all mapped to the same public key, e.g. to isolate a key_id swap from the
    "unknown key" path). Returns the (possibly mutated) record."""
    raw, _checksum, payload = publish_from_source.compile_from_source(source)
    private_key, pub = ts.generate_keypair()
    sha = ts.sha256_hex(raw)
    record = {
        "key_id": key_id,
        "publish_seq": publish_seq,
        "compiled_sha256": sha,
        "signature": ts.sign_manifest(
            private_key, key_id=key_id, publish_seq=publish_seq,
            compiled_sha256=sha, **ts.compiled_fields(payload)),
    }
    if mutate:
        mutate(record)
    pub_b64 = base64.b64encode(pub).decode()
    pubkeys = {kid: pub_b64 for kid in (trusted_ids or [key_id])}
    with open(os.path.join(source, "PUBKEYS.json"), "w", encoding="utf-8") as f:
        json.dump(pubkeys, f)
    with open(os.path.join(source, "SIGNATURE"), "w", encoding="utf-8") as f:
        json.dump(record, f)
    return record


def _write_published_version(repo, publish_seq):
    """Pre-seed api/termbase/version with a publish_seq (for the monotonic gate)."""
    api_dir = os.path.join(repo, "api", "termbase")
    os.makedirs(api_dir, exist_ok=True)
    with open(os.path.join(api_dir, "version"), "w", encoding="utf-8") as f:
        json.dump({"publish_seq": publish_seq, "checksum": "old", "termbase_version": "old"}, f)


class PublishFromSourceTests(unittest.TestCase):
    def test_dry_run_does_not_write_api_files(self):
        with tempfile.TemporaryDirectory() as repo:
            source = os.path.join(repo, "source")
            os.makedirs(source)
            copy_source_tree(source)
            _sign_source(source)

            result = publish_from_source.publish(source, repo, mode="dry-run")

            self.assertFalse(result["applied"])
            self.assertEqual(result["signature_errors"], [])
            self.assertFalse(os.path.exists(os.path.join(repo, "api", "termbase", "compiled")))
            self.assertEqual(result["current_count"], 2)
            self.assertEqual(result["previous_count"], 0)

    def test_apply_writes_compiled_and_version_with_signature(self):
        with tempfile.TemporaryDirectory() as repo:
            source = os.path.join(repo, "source")
            os.makedirs(source)
            copy_source_tree(source)
            record = _sign_source(source, key_id="k1", publish_seq=1)

            result = publish_from_source.publish(source, repo, mode="apply")

            self.assertTrue(result["applied"])
            self.assertEqual(result["signature_errors"], [])
            compiled = os.path.join(repo, "api", "termbase", "compiled")
            version = os.path.join(repo, "api", "termbase", "version")
            self.assertTrue(os.path.exists(compiled))
            self.assertTrue(os.path.exists(version))
            with open(version, "r", encoding="utf-8") as f:
                version_payload = json.load(f)
            self.assertEqual(version_payload["checksum"], result["checksum"])
            self.assertEqual(
                version_payload["download_url"],
                "https://roopoolimit.github.io/termbase-cdn/api/termbase/compiled",
            )
            # The signed fields are now carried in /version.
            self.assertEqual(version_payload["key_id"], "k1")
            self.assertEqual(version_payload["publish_seq"], 1)
            self.assertEqual(version_payload["compiled_sha256"], record["compiled_sha256"])
            self.assertEqual(version_payload["signature"], record["signature"])

    # ── signature gate: fail-closed paths (PR-B) ─────────────────────────────
    def _assert_dry_run_reports_then_apply_aborts(self, repo, source, marker):
        """dry-run surfaces the specific reason (no abort); apply fails closed and
        writes nothing."""
        result = publish_from_source.publish(source, repo, mode="dry-run")
        self.assertTrue(
            any(marker in e for e in result["signature_errors"]),
            f"expected a signature error containing {marker!r}, got {result['signature_errors']}",
        )
        with self.assertRaises(SystemExit):
            publish_from_source.publish(source, repo, mode="apply")
        self.assertFalse(os.path.exists(os.path.join(repo, "api", "termbase", "compiled")))

    def test_apply_without_signature_publishes_unsigned(self):
        # 2026-08-18: the offline signing step was cancelled by project decision.
        # An ABSENT signature publishes; version then asserts nothing about
        # provenance rather than carrying a claim nobody made.  (A PRESENT but
        # invalid signature is still fail-closed -- see the tests above.)
        with tempfile.TemporaryDirectory() as repo:
            source = os.path.join(repo, "source")
            os.makedirs(source)
            copy_source_tree(source)  # no _sign_source -> no SIGNATURE
            result = publish_from_source.publish(source, repo, mode="apply")
            self.assertEqual(result["signature_errors"], [])
            version_path = os.path.join(repo, "api", "termbase", "version")
            self.assertTrue(os.path.exists(os.path.join(repo, "api", "termbase", "compiled")))
            with open(version_path, "r", encoding="utf-8") as f:
                version_payload = json.load(f)
            for field in ("key_id", "publish_seq", "signature", "compiled_sha256"):
                self.assertNotIn(field, version_payload)
            self.assertEqual(version_payload["checksum"], result["checksum"])

    def test_runtime_contract_failure_aborts_before_publish(self):
        with tempfile.TemporaryDirectory() as repo:
            source = os.path.join(repo, "source")
            os.makedirs(source)
            copy_source_tree(source)
            with open(os.path.join(source, "runtime_contract.json"), "w", encoding="utf-8") as f:
                json.dump({
                    "schema_version": 1,
                    "required_surfaces": [{
                        "id": "missing-critical-alias",
                        "surface": "Finetuning",
                        "canonical_source": "Fine-tuning",
                    }],
                }, f)

            with self.assertRaises(SystemExit) as caught:
                publish_from_source.publish(source, repo, mode="dry-run")

            self.assertIn("missing-critical-alias", str(caught.exception))
            self.assertFalse(os.path.exists(os.path.join(repo, "api", "termbase", "compiled")))

    def test_apply_aborts_on_bad_signature(self):
        with tempfile.TemporaryDirectory() as repo:
            source = os.path.join(repo, "source")
            os.makedirs(source)
            copy_source_tree(source)
            _sign_source(source, mutate=lambda r: r.update(
                signature=base64.b64encode(b"\x00" * 64).decode()))
            self._assert_dry_run_reports_then_apply_aborts(repo, source, "does not verify")

    def test_apply_aborts_on_compiled_sha_mismatch(self):
        with tempfile.TemporaryDirectory() as repo:
            source = os.path.join(repo, "source")
            os.makedirs(source)
            copy_source_tree(source)
            _sign_source(source, mutate=lambda r: r.update(compiled_sha256="0" * 64))
            self._assert_dry_run_reports_then_apply_aborts(repo, source, "compiled_sha256 mismatch")

    def test_apply_aborts_on_unknown_key(self):
        with tempfile.TemporaryDirectory() as repo:
            source = os.path.join(repo, "source")
            os.makedirs(source)
            copy_source_tree(source)
            # SIGNATURE.key_id = k1, but PUBKEYS only trusts k2 -> unknown key.
            _sign_source(source, key_id="k1", trusted_ids=["k2"])
            self._assert_dry_run_reports_then_apply_aborts(repo, source, "unknown key_id")

    def test_apply_aborts_on_tampered_key_id(self):
        with tempfile.TemporaryDirectory() as repo:
            source = os.path.join(repo, "source")
            os.makedirs(source)
            copy_source_tree(source)
            # k2 IS trusted (not "unknown"), but the signature was made over
            # key_id=k1 — swapping it to k2 must FAIL verification, because key_id
            # is part of the canonical signed message (the PR-A blocker, enforced here).
            _sign_source(source, key_id="k1", trusted_ids=["k1", "k2"],
                         mutate=lambda r: r.update(key_id="k2"))
            self._assert_dry_run_reports_then_apply_aborts(repo, source, "does not verify")

    def test_apply_aborts_on_non_increasing_publish_seq(self):
        with tempfile.TemporaryDirectory() as repo:
            source = os.path.join(repo, "source")
            os.makedirs(source)
            copy_source_tree(source)
            _write_published_version(repo, publish_seq=5)
            _sign_source(source, publish_seq=5)  # equal -> not strictly greater
            self._assert_dry_run_reports_then_apply_aborts(repo, source, "strictly greater")

    def test_apply_succeeds_when_publish_seq_increases(self):
        with tempfile.TemporaryDirectory() as repo:
            source = os.path.join(repo, "source")
            os.makedirs(source)
            copy_source_tree(source)
            _write_published_version(repo, publish_seq=5)
            _sign_source(source, key_id="k1", publish_seq=6)

            result = publish_from_source.publish(source, repo, mode="apply")

            self.assertTrue(result["applied"])
            self.assertEqual(result["signature_errors"], [])
            with open(os.path.join(repo, "api", "termbase", "version"), encoding="utf-8") as f:
                self.assertEqual(json.load(f)["publish_seq"], 6)

    def test_real_source_snapshot_has_no_hash_warnings(self):
        # Regression: the COMMITTED source/ must match its own SOURCE_VERSION.txt,
        # or a real `publish_from_source.py --mode apply` aborts at the hash gate
        # before it even reaches the signature check. sync_to_cdn keeps them in
        # sync; this guards against editing a source file without re-syncing.
        source = os.path.dirname(os.path.abspath(__file__))
        self.assertEqual(
            publish_from_source.check_source_hashes(source), [],
            "committed source/ drifted from SOURCE_VERSION.txt — re-run sync_to_cdn",
        )

    def test_source_hash_mismatch_is_warning_not_failure(self):
        with tempfile.TemporaryDirectory() as repo:
            source = os.path.join(repo, "source")
            os.makedirs(source)
            copy_source_tree(source)
            with open(os.path.join(source, "compiled_schema.py"), "a", encoding="utf-8") as f:
                f.write("\n# local edit\n")

            result = publish_from_source.publish(source, repo, mode="dry-run")

            self.assertFalse(result["applied"])
            self.assertEqual(len(result["hash_warnings"]), 1)
            self.assertIn("compiled_schema.py", result["hash_warnings"][0])

    def test_source_hash_mismatch_blocks_apply(self):
        # dry-run reports; apply REFUSES — a tampered or partially-synced
        # snapshot must never reach production.
        with tempfile.TemporaryDirectory() as repo:
            source = os.path.join(repo, "source")
            os.makedirs(source)
            copy_source_tree(source)
            with open(os.path.join(source, "compiled_schema.py"), "a", encoding="utf-8") as f:
                f.write("\n# local edit\n")

            with self.assertRaises(SystemExit):
                publish_from_source.publish(source, repo, mode="apply")
            self.assertFalse(os.path.exists(os.path.join(repo, "api", "termbase", "compiled")))

    def test_empty_published_db_fails_schema_contract(self):
        # An accidentally empty published.db would otherwise publish an empty
        # termbase to every user. validate_compiled_payload blocks it.
        with tempfile.TemporaryDirectory() as repo:
            source = os.path.join(repo, "source")
            os.makedirs(source)
            copy_source_tree(source)
            db = os.path.join(source, "termbase.published.db")
            conn = sqlite3.connect(db)
            conn.execute("DELETE FROM terms")
            conn.commit()
            conn.close()
            # keep SOURCE_VERSION consistent so we exercise the schema gate,
            # not the hash gate
            with open(os.path.join(source, "SOURCE_VERSION.txt"), "w", encoding="utf-8") as f:
                f.write("backend_commit: test\ncopied_at: 2026-05-31T00:00:00Z\nfiles:\n")
                f.write(f"  termbase.published.db: {publish_from_source.sha256_file(db)}\n")

            with self.assertRaises(SystemExit):
                publish_from_source.publish(source, repo, mode="apply")


if __name__ == "__main__":
    unittest.main(verbosity=2)
