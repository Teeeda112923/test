# src/main.py
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple
from dateutil import parser

from feeds import (
    fetch_cisa_kev_ids,
    fetch_sec_gemini,
    fetch_nvd_recent,      # ← 使わなくてもOK（後方互換で残し）
    normalize_items,
    meets_policy,
    policy_reason,
)
from state import load_state, save_state
from wp import create_draft_html
from enrich import enrich_cve_item  # OpenAI＋Web補足

HERO_URL = "https://www.cybernote.click/wp-content/uploads/2025/11/hero-185.jpg"
JST = timezone(timedelta(hours=9))
POSTS_PER_DAY_LIMIT = 5

def _normalize_to_utc(iso_dt: str):
    if not iso_dt:
        return None
    try:
        s = iso_dt.strip()
        if len(s) == 10 and s[4] == "-" and s[7] == "-":
            s += "T00:00:00Z"
        dt = parser.isoparse(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception:
        return None

def _in_last_days(iso_dt: str, days: int) -> bool:
    dt = _normalize_to_utc(iso_dt)
    if dt is None:
        return False
    now = datetime.now(timezone.utc)
    if dt > now:
        return False
    return (now - dt) <= timedelta(days=days)

def _today_jst_str() -> str:
    return datetime.now(JST).strftime("%Y-%m-%d")

def _init_state_compat(state: Dict) -> Dict:
    state = state or {}
    if "seen" not in state or not isinstance(state["seen"], list):
        state["seen"] = []
    if "daily" not in state or not isinstance(state["daily"], dict):
        state["daily"] = {}
    return state

def _already_seen(state: Dict, cve: str) -> bool:
    return cve in state.get("seen", [])

def _mark_posted_today(state: Dict, cve: str) -> None:
    today = _today_jst_str()
    daily = state.setdefault("daily", {})
    lst = daily.setdefault(today, [])
    if cve not in lst:
        lst.append(cve)
    if cve not in state.setdefault("seen", []):
        state["seen"].append(cve)

def _today_posted_count(state: Dict) -> int:
    today = _today_jst_str()
    return len(state.get("daily", {}).get(today, []))

def _priority_key(item: Dict) -> Tuple:
    return (
        float(item.get("cvss", 0.0) or 0.0),
        bool(item.get("exploit_confirmed", False)),
    )

def main():
    lookback_days = int(os.getenv("DIGEST_LOOKBACK_DAYS", "7"))
    state = _init_state_compat(load_state())

    if _today_posted_count(state) >= POSTS_PER_DAY_LIMIT:
        print(f"[info] Already posted {POSTS_PER_DAY_LIMIT} items today (JST). Exit.")
        return

    # 最小限の収集（Sec-Gemini中心）
    cisa_ids = fetch_cisa_kev_ids()
    sec_items = fetch_sec_gemini()
    nvd_json = []  # fetch_nvd_recent() を使わない場合は空のままでOK

    items = normalize_items(sec_items, cisa_ids, nvd_json)
    print(f"[debug] fetched items: total={len(items)} (Sec-Gemini={len(sec_items)}, NVD={len(nvd_json)})")

    after_seen = after_recency = after_policy = 0
    candidates: List[Dict] = []

    for it in items:
        cve = (it.get("cve") or "").strip()
        if not cve:
            continue
        if _already_seen(state, cve):
            continue
        after_seen += 1

        if not _in_last_days(it.get("published"), lookback_days):
            continue
        after_recency += 1

        if not meets_policy(it):  # CVSS>=9.0 or exploited
            continue
        after_policy += 1

        candidates.append(it)

    print(f"[debug] after_seen={after_seen}, after_recency(<= {lookback_days}d)={after_recency}, after_policy={after_policy}")

    if not candidates:
        print("No candidates under the current policy (CVSS>=9.0 or exploited).")
        return

    candidates.sort(key=_priority_key, reverse=True)

    posted_count = _today_posted_count(state)
    posted_this_run = 0

    for it in candidates:
        if posted_count >= POSTS_PER_DAY_LIMIT:
            print(f"[info] Reached daily limit ({POSTS_PER_DAY_LIMIT}). Stop.")
            break

        # OpenAI＋検索で、vendor/product/悪用状況/参照/タイトル/本文を補完
        try:
            it = enrich_cve_item(it)
        except Exception as e:
            print(f"[warn] enrich failed for {it.get('cve')}: {e}")

        # タイトルは enrich が用意した日本語があれば優先
        title = it.get("title_ja")
        if not title:
            # フォールバック（最低限）
            cve = it.get("cve") or ""
            vendor = it.get("vendor") or ""
            product = it.get("product") or ""
            head = (vendor + " " + product).strip() or cve
            label = "【緊急】" if (float(it.get("cvss") or 0) >= 9.0 or bool(it.get("exploit_confirmed"))) else "【重要】"
            title = f"{label}{head} の脆弱性に関する注意喚起"

        # 本文は enrich が生成した body_md を優先
        body_md = it.get("body_md")
        if not body_md:
            # 最低限のフォールバック（OpenAI不可時）
            summary = it.get("summary") or it.get("description") or ""
            cvss = it.get("cvss") or "-"
            vendor = it.get("vendor") or "-"
            product = it.get("product") or "-"
            refs = it.get("references") or []
            refs_md = "\n".join([f"- {t or '参考情報'}: {u}" for t, u in refs if u])
            body_md = f"""## 脆弱性の概要
{summary}

| 項目 | 内容 |
|---|---|
| CVE番号 | {cve} |
| 公開日 | {it.get('published') or '-'} |
| 対象機器 | {(vendor + ' ' + product).strip()} |
| 種別 | - |
| CVSS | {cvss} |

## 参考情報
{refs_md or '-'}
"""

        try:
            post_id = create_draft_html(
                title=title,
                markdown_text=body_md,
                hero_image_url=HERO_URL,
            )
            print(f"[posted] {it.get('cve')} -> post_id={post_id} | {policy_reason(it)}")
        except Exception as e:
            print(f"[error] failed to post {it.get('cve')}: {e}")
            continue

        _mark_posted_today(state, it.get("cve"))
        save_state(state)

        posted_count += 1
        posted_this_run += 1

    if posted_this_run == 0:
        print("[info] Nothing new posted.")
    else:
        print(f"[done] Posted {posted_this_run} item(s) this run. Today total: {posted_count}/{POSTS_PER_DAY_LIMIT}")

if __name__ == "__main__":
    main()

