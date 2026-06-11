"""
termbase compiler — 生成 extension 可消费的 compiled_termbase.json + SHA-256 checksum
模块级缓存：/version 和 /compiled 共享同一份字节，避免漂移
"""

import json, re, time, hashlib, sqlite3, os
from datetime import date
from compiled_schema import KEEP_ENGLISH_MODES

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "termbase.published.db")

# 模块级缓存
_cached_bytes = None
_cached_checksum = None
_cached_at = 0
CACHE_TTL = 300  # 5 minutes

_PLURAL_WORD_RE = re.compile(r"^[A-Za-z]{2,}$")


def _plural_variant(term_text: str) -> str | None:
    """Best-effort English plural for a translate-as term, or None.

    扩展端的 ASCII 词边界匹配不到复数（"Agents" ≠ "Agent"），人工 aliases 兜不全。
    多词术语只复数化最后一个词（"Large Language Model" → "Large Language Models"），
    缩写直接 +s（"LLM" → "LLMs"）。保守跳过：末词含数字/连字符/符号，或本就以 s
    结尾（可能已是复数）。"""
    text = (term_text or "").strip()
    if not text:
        return None
    prefix, _, last = text.rpartition(" ")
    if not _PLURAL_WORD_RE.match(last):
        return None
    lower = last.lower()
    if lower.endswith("s"):
        return None
    if lower.endswith(("x", "z", "ch", "sh")):
        plural = last + "es"
    elif lower.endswith("y") and lower[-2] not in "aeiou":
        plural = last[:-1] + "ies"
    else:
        plural = last + "s"
    return (prefix + " " + plural) if prefix else plural


# priority = 已知误译的最高 severity。它回答的是"40 条指令上限挤爆时，谁该留下"——
# 最强的信号就是"模型在这个词上有记录在案的翻车史"。无 wrong 记录 → 0（字段不发，
# 省 payload）；扩展端缺省按 0 处理，向后兼容旧 payload。
_SEVERITY_PRIORITY = {"high": 3, "medium": 2, "low": 1}


def _priority_for(wrongs: list) -> int:
    p = 0
    for w in wrongs:
        p = max(p, _SEVERITY_PRIORITY.get(str(w.get("severity") or "").lower(), 1))
    return p


def _build_compiled_dict() -> dict:
    """从 v3 DB 编译 extension 可消费的结构"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # 筛选：所有 approved 术语。语言对由每条 term 的 source_lang/target_lang 显式携带，
    # 扩展运行时按目标语言过滤，避免未来多语言术语被 compiler 静默丢弃。
    terms_rows = conn.execute("""
        SELECT id, source_term, target_term, source_lang, target_lang, preferred_translation,
               keep_english_v2, domain_tags
        FROM terms
        WHERE status = 'approved'
        ORDER BY source_lang, target_lang, source_term
    """).fetchall()

    # 合成复数别名的全局冲突防护：一个变体若已被任何 approved 术语的 source_term
    # 或人工 alias 占用，则不生成——既不在 compiled 里制造 lint 看不见的 alias
    # 撞车，也保证人工数据永远赢过合成数据。
    alias_map: dict = {}
    for r in conn.execute("""
        SELECT a.term_id, a.alias FROM term_aliases a
        JOIN terms t ON t.id = a.term_id
        WHERE t.status = 'approved' ORDER BY a.id
    """).fetchall():
        alias_map.setdefault(r["term_id"], []).append(r["alias"])
    claimed = {t["source_term"].strip().lower() for t in terms_rows}
    for arr in alias_map.values():
        for a in arr:
            claimed.add(a.strip().lower())

    terms = []
    for t in terms_rows:
        tid = t["id"]

        keep_mode = t["keep_english_v2"] if (t["keep_english_v2"] or "") in KEEP_ENGLISH_MODES else "never"

        # aliases → 扁平字符串数组（人工别名在前，合成复数在后）
        aliases = list(alias_map.get(tid, []))
        # 合成复数仅限 translate-as 术语 + 英文源：always 品牌词跳过——专有名词
        # 复数没有意义（"Claude 4 Opuses"），且它们走 [##Kn##] 掩码路径。
        if keep_mode != "always" and str(t["source_lang"] or "").lower().startswith("en"):
            for cand in [t["source_term"]] + list(aliases):
                variant = _plural_variant(cand)
                if variant and variant.lower() not in claimed:
                    claimed.add(variant.lower())
                    aliases.append(variant)

        # wrong_translations
        wrong_rows = conn.execute(
            "SELECT wrong_translation, severity FROM term_wrong_translations WHERE term_id = ? ORDER BY id", (tid,)
        ).fetchall()
        wrongs = [{"wrong": w["wrong_translation"], "severity": w["severity"]} for w in wrong_rows]

        # contexts (前向兼容)
        ctx_rows = conn.execute(
            "SELECT context_type, definition_zh FROM term_contexts WHERE term_id = ? ORDER BY id", (tid,)
        ).fetchall()
        contexts = [{"type": c["context_type"], "zh": c["definition_zh"]} for c in ctx_rows]

        # relations (前向兼容)
        rel_rows = conn.execute(
            "SELECT related_term_text, relation_type, relation_weight FROM term_relations WHERE term_id = ? ORDER BY relation_weight DESC", (tid,)
        ).fetchall()
        relations = [{
            "related": r["related_term_text"],
            "type": r["relation_type"],
            "weight": r["relation_weight"],
        } for r in rel_rows]

        # domain_tags: DB 里是 JSON 字符串
        domain_tags = []
        raw_tags = t["domain_tags"] or ""
        if raw_tags:
            try:
                domain_tags = json.loads(raw_tags)
            except json.JSONDecodeError:
                domain_tags = [raw_tags]

        compiled_term = {
            "source_term": t["source_term"],
            "target_term": t["target_term"],
            "source_lang": t["source_lang"],
            "target_lang": t["target_lang"],
            "preferred_translation": t["preferred_translation"] or "",
            "keep_english_mode": keep_mode,
            "aliases": aliases,
            "wrong_translations": wrongs,
            "domain_tags": domain_tags,
            "contexts": contexts,
            "relations": relations,
        }
        # 稀疏字段：仅 >0 才发（约 1/10 的术语有 wrong 记录），其余省 payload。
        priority = _priority_for(wrongs)
        if priority:
            compiled_term["priority"] = priority
        terms.append(compiled_term)

    conn.close()

    return {
        "schema_version": "v3",
        "termbase_version": date.today().strftime("%Y.%m.%d"),
        "min_extension_version": "0.0.0",
        "terms": terms,
    }


def compile_termbase() -> tuple:
    """返回 (json_bytes, checksum_hex)"""
    data = _build_compiled_dict()
    json_str = json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=False)
    json_bytes = json_str.encode("utf-8")
    checksum = hashlib.sha256(json_bytes).hexdigest()
    return json_bytes, checksum


def get_compiled_cached() -> tuple:
    """缓存获取 compiled bytes + checksum；DB 文件变动自动失效"""
    global _cached_bytes, _cached_checksum, _cached_at
    now = time.time()
    db_mtime = os.path.getmtime(DB_PATH)
    if _cached_bytes is None or (now - _cached_at) > CACHE_TTL or db_mtime > _cached_at:
        _cached_bytes, _cached_checksum = compile_termbase()
        _cached_at = now
    return _cached_bytes, _cached_checksum


def invalidate_termbase_cache():
    """CRUD 操作后清除缓存"""
    global _cached_bytes, _cached_checksum, _cached_at
    _cached_bytes = None
    _cached_checksum = None
    _cached_at = 0


# ── CLI 调试 ────────────────────────────────────

if __name__ == "__main__":
    invalidate_termbase_cache()
    b, cs = get_compiled_cached()
    data = json.loads(b.decode("utf-8"))
    print(f"schema: {data['schema_version']}")
    print(f"version: {data['termbase_version']}")
    print(f"terms: {len(data['terms'])}")
    print(f"checksum: {cs}")
    print(f"bytes: {len(b)}")
    # 验证 checksum 一致
    cs2 = hashlib.sha256(b).hexdigest()
    print(f"verify: {cs == cs2}")
    # 抽样
    for t in data["terms"][:3]:
        print(f"  {t['source_term']} → {t['target_term']} (keep={t['keep_english_mode']}, aliases={t['aliases']})")
