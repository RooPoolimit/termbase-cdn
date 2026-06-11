import json
import os
import shutil
import sqlite3
import tempfile
import unittest

import publish_from_source


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
    for name in ["compiled_schema.py", "termbase_compiler.py", "publish_from_source.py"]:
        shutil.copy2(os.path.join(source_dir, name), os.path.join(target, name))
    write_runtime_db(os.path.join(target, "termbase.published.db"))
    hashes = {
        name: publish_from_source.sha256_file(os.path.join(target, name))
        for name in ["compiled_schema.py", "termbase_compiler.py", "termbase.published.db"]
    }
    with open(os.path.join(target, "SOURCE_VERSION.txt"), "w", encoding="utf-8") as f:
        f.write("backend_commit: test\n")
        f.write("copied_at: 2026-05-31T00:00:00Z\n")
        f.write("files:\n")
        for name in sorted(hashes):
            f.write(f"  {name}: {hashes[name]}\n")


class PublishFromSourceTests(unittest.TestCase):
    def test_dry_run_does_not_write_api_files(self):
        with tempfile.TemporaryDirectory() as repo:
            source = os.path.join(repo, "source")
            os.makedirs(source)
            copy_source_tree(source)

            result = publish_from_source.publish(source, repo, mode="dry-run")

            self.assertFalse(result["applied"])
            self.assertFalse(os.path.exists(os.path.join(repo, "api", "termbase", "compiled")))
            self.assertEqual(result["current_count"], 2)
            self.assertEqual(result["previous_count"], 0)

    def test_apply_writes_compiled_and_version(self):
        with tempfile.TemporaryDirectory() as repo:
            source = os.path.join(repo, "source")
            os.makedirs(source)
            copy_source_tree(source)

            result = publish_from_source.publish(source, repo, mode="apply")

            self.assertTrue(result["applied"])
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
