"""
termbase compiler — 生成 extension 可消费的 compiled_termbase.json + SHA-256 checksum
模块级缓存：/version 和 /compiled 共享同一份字节，避免漂移
"""

import json, re, time, hashlib, sqlite3, os
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

    # 筛选：所有 approved 术语。语言对由每条 term 的 source_lang/target_lang 显式携带，
    # 扩展运行时按目标语言过滤，避免未来多语言术语被 compiler 静默丢弃。
    terms_rows = conn.execute(f"""
        SELECT id, source_term, target_term, source_lang, target_lang, preferred_translation,
               keep_english_v2, domain_tags{homograph_col}
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

        # aliases → 扁平字符串数组（人工别名在前，合成复数在后）
        aliases = list(alias_map.get(tid, []))
        # 合成复数仅限 translate-as 术语 + 英文源：always 品牌词跳过——专有名词
        # 复数没有意义（"Claude 4 Opuses"），且它们走 [##Kn##] 掩码路径。
        # 游戏包里大量条目是角色、地点、作品和道具专名，自动复数会造出
        # "Links" / "The Legend of Zeldas" 这类误命中 alias；需要复数的游戏名词
        # 应显式录入人工 alias。
        if keep_mode != "always" and "game" not in domain_tags and str(t["source_lang"] or "").lower().startswith("en"):
            for cand in [t["source_term"]] + list(aliases):
                variant = _plural_variant(cand)
                if variant and variant.lower() not in claimed:
                    claimed.add(variant.lower())
                    aliases.append(variant)

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
        # 稀疏字段：仅 >0 才发（约 1/10 的术语有 wrong 记录），其余省 payload。
        priority = _priority_for(wrongs)
        if priority:
            compiled_term["priority"] = priority
        # 危险度分级（2026-07-04）：homograph=0（人工审定的独特专名）发
        # ungated:1——扩展端域硬过滤对它放行，无域信号也激活（Hasselblad、
        # Zenyatta 不再被 Link/Canon 连坐）。homograph=1 或 NULL（未审）都
        # 不发——运行时缺省 = 现行门控行为，fail-closed。
        if has_homograph and t["homograph"] == 0:
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
