"""
termbase compiler — 生成 extension 可消费的 compiled_termbase.json + SHA-256 checksum
模块级缓存：/version 和 /compiled 共享同一份字节，避免漂移
"""

import json, time, hashlib, sqlite3, os
from compiled_schema import KEEP_ENGLISH_MODES

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "termbase.published.db")

# 模块级缓存
_cached_bytes = None
_cached_checksum = None
_cached_at = 0
_cached_db_stamp = None
CACHE_TTL = 300  # 5 minutes


def _db_change_stamp() -> tuple:
    """DB 变化检测戳：主文件 mtime + -wal 的 mtime/size。

    库是 WAL 模式：跨进程提交只写 -wal、不动主文件 mtime——只看主文件会让
    外部写入（如 release workflow 对着运行中的 server 写库）后的 /compiled
    陈旧到 TTL 到期。用"变化"而非"变大"比较，恢复旧备份（mtime 变小）也能
    触发失效。-shm 刻意不看：读连接也会碰它，会造成缓存永远 miss。"""
    stamp = [None, None, None]
    try:
        stamp[0] = os.path.getmtime(DB_PATH)
    except OSError:
        pass
    try:
        wal = DB_PATH + "-wal"
        stamp[1] = os.path.getmtime(wal)
        stamp[2] = os.path.getsize(wal)
    except OSError:
        pass
    return tuple(stamp)

# priority = 已知误译的最高 severity。它回答的是"40 条指令上限挤爆时，谁该留下"——
# 最强的信号就是"模型在这个词上有记录在案的翻车史"。无 wrong 记录 → 0（字段不发，
# 省 payload）；扩展端缺省按 0 处理，向后兼容旧 payload。
_SEVERITY_PRIORITY = {"high": 3, "medium": 2, "low": 1}
POLICY_MODES = frozenset({"preserve_exact", "translate_exact", "contextual", "preferred"})


def _priority_for(wrongs: list) -> int:
    p = 0
    for w in wrongs:
        p = max(p, _SEVERITY_PRIORITY.get(str(w.get("severity") or "").lower(), 1))
    return p


def _surface_key(value) -> str:
    """Mirror the extension's termKey for collision ownership checks."""
    return " ".join(str(value or "").strip().lower().split())


def _content_version(terms: list) -> str:
    """Content-derived termbase_version: a stable 16-hex digest of the compiled
    term list. Identical data always yields the same version (and therefore the
    same checksum), regardless of WHEN it is compiled — replacing the old
    date.today() value, which churned the checksum daily for unchanged data and
    let same-day republishes collide. Human 'when' lives in the un-hashed
    `generated_at` field of the /version envelope, never in the hashed payload."""
    canonical = json.dumps(terms, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _build_compiled_dict() -> dict:
    """从 v3 DB 编译 extension 可消费的结构"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        return _build_compiled_dict_inner(conn)
    finally:
        # 此前编译中途抛异常会漏关连接（Windows 上文件句柄挂住临时目录清理）
        conn.close()


def _build_compiled_dict_inner(conn) -> dict:
    # homograph 列 2026-07-04 引入；旧 schema（老备份/测试 fixture）没有该列
    # ——等价于全部未审（NULL）：不发 ungated，照旧门控，向后兼容。
    has_homograph = any(
        r["name"] == "homograph" for r in conn.execute("PRAGMA table_info(terms)").fetchall()
    )
    homograph_col = ", homograph" if has_homograph else ""
    term_columns = {r["name"] for r in conn.execute("PRAGMA table_info(terms)").fetchall()}
    has_policy = {"policy_mode", "ambiguity", "policy_reviewed"}.issubset(term_columns)
    policy_cols = ", policy_mode, ambiguity, policy_reviewed" if has_policy else ""

    # 筛选：所有 approved 术语。语言对由每条 term 的 source_lang/target_lang 显式携带，
    # 扩展运行时按目标语言过滤，避免未来多语言术语被 compiler 静默丢弃。
    terms_rows = conn.execute(f"""
        SELECT id, source_term, target_term, source_lang, target_lang, preferred_translation,
               keep_english_v2, domain_tags{homograph_col}{policy_cols}
        FROM terms
        WHERE status = 'approved'
        ORDER BY source_lang, target_lang, source_term
    """).fetchall()

    # Runtime aliases are explicit authoring data. Earlier compiler versions
    # guessed English plurals and generated hundreds of invalid surfaces such
    # as "A/B Testings", "Yis", and product-name plurals. Morphology is a
    # semantic authoring decision, so the compiler now emits manual aliases
    # only; release coverage tests identify missing high-value variants.
    alias_map: dict = {}
    for r in conn.execute("""
        SELECT a.term_id, a.alias FROM term_aliases a
        JOIN terms t ON t.id = a.term_id
        WHERE t.status = 'approved' ORDER BY a.id
    """).fetchall():
        alias_map.setdefault(r["term_id"], []).append(r["alias"])

    # `ungated` is currently term-level metadata, while ownership collisions
    # are surface-level. If ANY canonical/alias surface has another approved
    # owner, emitting term-level ungated would let that ambiguous spelling
    # bypass domain gating. Live example: game term "Sigma (Overwatch)" was
    # reviewed unique (homograph=0) but its alias "Sigma" also belongs to the
    # imaging term; ungated made the game translation fire on ai_ml pages.
    # Suppress ungated for the whole term until the payload can express
    # surface-level gating. The runtime also enforces this defensively.
    surface_owners: dict[str, set[int]] = {}
    for row in terms_rows:
        key = _surface_key(row["source_term"])
        if key:
            surface_owners.setdefault(key, set()).add(row["id"])
    for term_id, aliases in alias_map.items():
        for alias in aliases:
            key = _surface_key(alias)
            if key:
                surface_owners.setdefault(key, set()).add(term_id)
    collision_term_ids = {
        term_id
        for owners in surface_owners.values()
        if len(owners) > 1
        for term_id in owners
    }

    # wrong_translations 一次性取回（此前每术语一查，~1700 查询/编译）。
    # 全局 ORDER BY w.id 保持每术语内的行序与旧逐条查询一致——顺序进
    # 编译产物，动它就动 checksum。
    wrongs_map: dict = {}
    for r in conn.execute("""
        SELECT w.term_id, w.wrong_translation, w.severity
        FROM term_wrong_translations w
        JOIN terms t ON t.id = w.term_id
        WHERE t.status = 'approved' ORDER BY w.id
    """).fetchall():
        wrongs_map.setdefault(r["term_id"], []).append(
            {"wrong": r["wrong_translation"], "severity": r["severity"]})

    senses_map: dict = {}
    has_senses = bool(conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='term_senses'"
    ).fetchone())
    if has_senses:
        for r in conn.execute("""
            SELECT s.term_id, s.sense_key, s.target_translation, s.domain_tags,
                   s.when_en, s.avoid_translations, s.priority
            FROM term_senses s JOIN terms t ON t.id=s.term_id
            WHERE t.status='approved' AND s.status='approved' ORDER BY s.id
        """).fetchall():
            try:
                sense_domains = json.loads(r["domain_tags"] or "[]")
            except json.JSONDecodeError:
                sense_domains = []
            try:
                avoid = json.loads(r["avoid_translations"] or "[]")
            except json.JSONDecodeError:
                avoid = []
            senses_map.setdefault(r["term_id"], []).append({
                "id": r["sense_key"], "target": r["target_translation"],
                "domains": sense_domains, "when": r["when_en"],
                "avoid": avoid, "priority": r["priority"],
            })

    terms = []
    for t in terms_rows:
        tid = t["id"]

        keep_mode = t["keep_english_v2"] if (t["keep_english_v2"] or "") in KEEP_ENGLISH_MODES else "never"

        # domain_tags: DB 里是 JSON 字符串
        domain_tags = []
        raw_tags = t["domain_tags"] or ""
        if raw_tags:
            try:
                domain_tags = json.loads(raw_tags)
            except json.JSONDecodeError:
                domain_tags = [raw_tags]

        # aliases → 扁平字符串数组（仅人工审核数据）
        aliases = list(alias_map.get(tid, []))

        wrongs = wrongs_map.get(tid, [])

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
        }
        if has_policy and (t["policy_mode"] or "") in POLICY_MODES:
            policy_mode = t["policy_mode"]
            if policy_mode in {"preserve_exact", "translate_exact"} and (
                t["ambiguity"] != "unique" or t["policy_reviewed"] != 1
            ):
                raise ValueError(
                    f"term {tid} {policy_mode} requires ambiguity=unique and policy_reviewed=1"
                )
            compiled_term["policy_mode"] = policy_mode
            if t["ambiguity"]:
                compiled_term["ambiguity"] = t["ambiguity"]
            if policy_mode == "contextual":
                compiled_term["senses"] = list(senses_map.get(tid, []))
        # 稀疏字段：仅 >0 才发（约 1/10 的术语有 wrong 记录），其余省 payload。
        priority = _priority_for(wrongs)
        if priority:
            compiled_term["priority"] = priority
        # 危险度分级（2026-07-04）：homograph=0（人工审定的独特专名）发
        # ungated:1——但仅限 canonical/alias 均无多 owner 冲突的术语。
        # 冲突术语必须继续走领域门控；homograph=1 或 NULL（未审）同样不发，
        # 运行时缺省 = fail-closed。
        if (
            has_homograph
            and t["homograph"] == 0
            and tid not in collision_term_ids
        ):
            compiled_term["ungated"] = 1
        terms.append(compiled_term)

    return {
        "schema_version": "v3",
        "termbase_version": _content_version(terms),
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
    """缓存获取 compiled bytes + checksum；DB 文件（含 WAL）变动自动失效"""
    global _cached_bytes, _cached_checksum, _cached_at, _cached_db_stamp
    now = time.time()
    stamp = _db_change_stamp()
    if _cached_bytes is None or (now - _cached_at) > CACHE_TTL or stamp != _cached_db_stamp:
        # 存"编译前"的戳：编译期间落进来的写入会让下次调用的新戳 != 它，
        # 保守地多编译一次而不是漏掉（与旧实现 _cached_at 取编译前时刻同理）。
        _cached_db_stamp = stamp
        _cached_bytes, _cached_checksum = compile_termbase()
        _cached_at = now
    return _cached_bytes, _cached_checksum


def invalidate_termbase_cache():
    """CRUD 操作后清除缓存"""
    global _cached_bytes, _cached_checksum, _cached_at, _cached_db_stamp
    _cached_bytes = None
    _cached_checksum = None
    _cached_at = 0
    _cached_db_stamp = None


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
