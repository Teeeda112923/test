from __future__ import annotations

import os
import json
import time
import csv
from typing import Dict, List, Tuple, Any
from datetime import datetime, timedelta, timezone

import requests
from dateutil import parser as dtparser

# ───────────────────────────────────────────────────────────
# 環境変数
# ───────────────────────────────────────────────────────────
SEC_GEMINI_FEED_URL = (
    os.getenv("SEC_GEMINI_FEED_URL", "").strip()
    or "https://raw.githubusercontent.com/Teeeda112923/sec-gemini-main/main/output/latest.json"
)
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
LOOKBACK_DAYS = int(os.getenv("DIGEST_LOOKBACK_DAYS", "7"))


# ───────────────────────────────────────────────────────────
# 共通ユーティリティ
# ───────────────────────────────────────────────────────────
def _safe_str(x: Any) -> str:
    return "" if x is None else str(x)


def _to_float(x: Any) -> float | None:
    try:
        return float(x)
    except Exception:
        return None


def _normalize_to_utc(iso_dt: str | None) -> str | None:
    """ISO8601/日付のみ/naiveも受け取り、UTC aware ISO8601文字列で返す"""
    if not iso_dt:
        return None
    try:
        s = iso_dt.strip()
        if len(s) == 10 and s[4] == "-" and s[7] == "-":
            s = s + "T00:00:00Z"
        dt = dtparser.isoparse(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def _within_days(iso_dt: str | None, days: int) -> bool:
    dt_s = _normalize_to_utc(iso_dt)
    if not dt_s:
        return False
    try:
        dt = dtparser.isoparse(dt_s)
        now = datetime.now(timezone.utc)
        if dt > now:
            return False
        return (now - dt) <= timedelta(days=days)
    except Exception:
        return False


# ───────────────────────────────────────────────────────────
# CISA KEV
# ───────────────────────────────────────────────────────────
def fetch_cisa_kev_ids() -> set[str]:
    urls = [
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv",
    ]
    kev_ids: set[str] = set()
    for url in urls:
        try:
            r = requests.get(url, timeout=30)
            r.raise_for_status()
            ct = (r.headers.get("Content-Type") or "").lower()
            if "json" in ct:
                data = r.json()
                vulns = data.get("vulnerabilities") or data.get("Vulnerabilities") or []
                for v in vulns:
                    cve = (v.get("cveID") or v.get("cveId") or "").strip()
                    if cve:
                        kev_ids.add(cve)
                if kev_ids:
                    return kev_ids
            else:
                reader = csv.DictReader(r.text.splitlines())
                for row in reader:
                    cve = (row.get("cveID") or row.get("cveId") or "").strip()
                    if cve:
                        kev_ids.add(cve)
                if kev_ids:
                    return kev_ids
        except Exception:
            continue
    return kev_ids


# ───────────────────────────────────────────────────────────
# Sec-Gemini latest.json
# ───────────────────────────────────────────────────────────
def fetch_sec_gemini() -> List[Dict]:
    """Sec-Geminiのlatest.jsonを取得（リトライ付き）"""
    url = SEC_GEMINI_FEED_URL
    if not url:
        return []
    for attempt in range(3):
        try:
            r = requests.get(url, timeout=30)
            if r.status_code == 404:
                time.sleep(5)
                continue
            r.raise_for_status()
            data = r.json()
            if isinstance(data, dict) and isinstance(data.get("items"), list):
                return data["items"]
            if isinstance(data, list):
                return data
            return []
        except Exception as e:
            if attempt == 2:
                print(f"[warn] failed to fetch Sec-Gemini feed: {e}")
            time.sleep(3)
    return []


# ───────────────────────────────────────────────────────────
# NVD 取得（2.0 API）
# ───────────────────────────────────────────────────────────
def _nvd_headers() -> Dict[str, str]:
    h = {"User-Agent": "VulnDigest/1.0"}
    if NVD_API_KEY:
        h["apiKey"] = NVD_API_KEY
    return h


def _nvd_window_params(days: int) -> Tuple[str, str]:
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)

    def fmt(dt: datetime) -> str:
        return dt.isoformat(timespec="seconds").replace("+00:00", "Z")

    return fmt(start), fmt(now)


def _extract_nvd_cvss(cve: Dict) -> float | None:
    metrics = (cve.get("metrics") or {})
    for key in ("cvssMetricV40", "cvssMetricV4", "cvssMetricV31", "cvssMetricV30"):
        if key in metrics and isinstance(metrics[key], list) and metrics[key]:
            data = metrics[key][0].get("cvssData", {})
            score = _to_float(data.get("baseScore"))
            if score is not None:
                return score
    return None


def _extract_nvd_refs(cve: Dict) -> List[Tuple[str, str]]:
    refs: List[Tuple[str, str]] = []
    for ref in (cve.get("references") or []):
        url = ref.get("url") or ""
        name = ref.get("source") or ref.get("tags") or ""
        if isinstance(name, list):
            name = ", ".join([_safe_str(t) for t in name])
        title = ref.get("name") or name or "reference"
        if url:
            refs.append((title, url))
    return refs


def _extract_nvd_vendor_product(cve: Dict) -> Tuple[str, str]:
    configs = cve.get("configurations") or {}
    nodes = configs.get("nodes") if isinstance(configs, dict) else configs
    if not isinstance(nodes, list):
        return "", ""
    for node in nodes:
        matches = node.get("cpeMatch") or []
        for m in matches:
            cpe = m.get("criteria") or m.get("cpe23Uri") or ""
            parts = cpe.split(":")
            if len(parts) >= 5:
                vendor = parts[3].replace("_", " ")
                product = parts[4].replace("_", " ")
                return vendor, product
    return "", ""


def fetch_nvd_recent(days: int = LOOKBACK_DAYS, max_results: int = 200) -> List[Dict]:
    """NVD APIから直近のCVEを安全に取得"""
    start, end = _nvd_window_params(days)
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"pubStartDate": start, "pubEndDate": end, "resultsPerPage": str(max_results)}

    try:
        r = requests.get(url, headers=_nvd_headers(), params=params, timeout=60)
        r.raise_for_status()
        data = r.json()

        vulns: List[Dict] = []
        if isinstance(data, dict):
            vulns = data.get("vulnerabilities") or data.get("Vulnerabilities") or []
        elif isinstance(data, list):
            if data and isinstance(data[0], dict) and ("cve" in data[0] or "CVE" in data[0]):
                vulns = data
            else:
                print(f"[warn] NVD returned unexpected list payload (len={len(data)})")
                return []

        if not isinstance(vulns, list):
            print("[warn] NVD payload malformed, expected list")
            return []

        items: List[Dict] = []
        for v in vulns:
            c = v.get("cve") if isinstance(v, dict) else None
            if not isinstance(c, dict):
                c = v if isinstance(v, dict) else {}
            cve_id = (c.get("id") or "").strip()
            if not cve_id:
                continue

            descs = c.get("descriptions") or []
            summary = ""
            for d in descs:
                if isinstance(d, dict) and ((d.get("lang") or "").lower() in ("en", "ja")):
                    summary = d.get("value") or ""
                    break

            published = c.get("published") or c.get("publishedDate")
            refs = _extract_nvd_refs(c)
            vendor, product = _extract_nvd_vendor_product(c)
            cvss = _extract_nvd_cvss(c)

            items.append({
                "source": "nvd",
                "cve": cve_id,
                "summary": summary,
                "description": summary,
                "published": _normalize_to_utc(published),
                "cvss": cvss,
                "vendor": vendor,
                "product": product,
                "references": refs,
                "exploit_confirmed": False,
            })
        return items
    except Exception as e:
        print(f"[warn] failed to fetch NVD: {e}")
        return []


# ───────────────────────────────────────────────────────────
# 正規化とポリシー
# ───────────────────────────────────────────────────────────
def _mk_ref_list(refs: Any) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if not refs:
        return out
    if isinstance(refs, dict):
        t = _safe_str(refs.get("title") or "reference")
        u = _safe_str(refs.get("url"))
        if u:
            out.append((t, u))
        return out
    if isinstance(refs, list):
        for r in refs:
            if isinstance(r, dict):
                t = _safe_str(r.get("title") or r.get("name") or "reference")
                u = _safe_str(r.get("url"))
                if u:
                    out.append((t, u))
            elif isinstance(r, (list, tuple)) and len(r) >= 2:
                t = _safe_str(r[0]) or "reference"
                u = _safe_str(r[1])
                if u:
                    out.append((t, u))
            elif isinstance(r, str) and r.startswith("http"):
                out.append(("reference", r))
    return out


def normalize_items(sec_items: List[Dict], cisa_ids: set[str], nvd_items: List[Dict]) -> List[Dict]:
    merged: Dict[str, Dict] = {}

    for it in nvd_items:
        cve = (it.get("cve") or "").strip()
        if not cve:
            continue
        merged[cve] = {
            "cve": cve,
            "summary": _safe_str(it.get("summary")),
            "description": _safe_str(it.get("description")),
            "published": _normalize_to_utc(_safe_str(it.get("published"))),
            "cvss": _to_float(it.get("cvss")),
            "vendor": _safe_str(it.get("vendor")),
            "product": _safe_str(it.get("product")),
            "references": _mk_ref_list(it.get("references")),
            "cisa_kev": cve in cisa_ids,
            "exploit_confirmed": bool(it.get("exploit_confirmed")),
            "source": "nvd",
        }

    for it in sec_items:
        cve = _safe_str(it.get("cve") or it.get("cveId") or it.get("id")).strip()
        if not cve:
            continue
        base = merged.get(cve, {})
        summary = _safe_str(it.get("summary") or it.get("title") or base.get("summary"))
        desc = _safe_str(base.get("description") or summary)
        published = _normalize_to_utc(_safe_str(it.get("published") or base.get("published")))
        cvss = _to_float(it.get("cvss")) or base.get("cvss")
        vendor = _safe_str(it.get("vendor") or base.get("vendor"))
        product = _safe_str(it.get("product") or base.get("product"))
        refs = _mk_ref_list(it.get("references")) or base.get("references") or []
        exploited = bool(it.get("exploited") or base.get("exploit_confirmed"))

        merged[cve] = {
            "cve": cve,
            "summary": summary,
            "description": desc,
            "published": published,
            "cvss": cvss,
            "vendor": vendor,
            "product": product,
            "references": refs,
            "cisa_kev": (cve in cisa_ids) or bool(base.get("cisa_kev")),
            "exploit_confirmed": exploited,
            "source": "sec-gemini+nvd" if base else "sec-gemini",
        }

    items = list(merged.values())
    print(f"[debug] fetched items: total={len(items)} (Sec-Gemini={len(sec_items)}, NVD={len(nvd_items)})")
    return items


# ───────────────────────────────────────────────────────────
# ポリシー
# ───────────────────────────────────────────────────────────
def meets_policy(item: Dict) -> bool:
    cvss = _to_float(item.get("cvss")) or 0.0
    exploited = bool(item.get("exploit_confirmed"))
    return (cvss >= 9.0) or exploited


def policy_reason(item: Dict) -> str:
    cvss_val = _to_float(item.get("cvss"))
    cvss = 0.0 if cvss_val is None else cvss_val
    exploited = bool(item.get("exploit_confirmed"))
    if (cvss >= 9.0) or exploited:
        conds = []
        if cvss >= 9.0:
            conds.append(f"CVSS {cvss:.1f}≥9.0")
        if exploited:
            conds.append("実悪用確認済み")
        return "掲載対象: " + " / ".join(conds)
    else:
        reasons = [f"CVSS {cvss:.1f}<9.0"]
        if not exploited:
            reasons.append("実悪用未確認")
        return "除外: " + " / ".join(reasons)


# ───────────────────────────────────────────────────────────
# デバッグ用
# ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    kev = fetch_cisa_kev_ids()
    sec = fetch_sec_gemini()
    nvd = fetch_nvd_recent(days=LOOKBACK_DAYS)
    items = normalize_items(sec, kev, nvd)
    recent = [it for it in items if _within_days(it.get("published"), LOOKBACK_DAYS)]
    passed = [it for it in recent if meets_policy(it)]
    print(f"[debug] after_seen={len(items)}, after_recency(<= {LOOKBACK_DAYS}d)={len(recent)}, after_policy={len(passed)}")
    for it in passed[:5]:
        print(json.dumps({
            "cve": it.get("cve"),
            "cvss": it.get("cvss"),
            "published": it.get("published"),
            "vendor": it.get("vendor"),
            "product": it.get("product"),
            "cisa_kev": it.get("cisa_kev"),
            "exploited": it.get("exploit_confirmed"),
            "reason": policy_reason(it),
        }, ensure_ascii=False))

