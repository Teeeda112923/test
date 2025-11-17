# src/enrich.py
from __future__ import annotations

import os
import re
import time
import html
from typing import Dict, List, Tuple
from urllib.parse import quote_plus

import requests

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
SERPAPI_API_KEY = os.getenv("SERPAPI_API_KEY", "").strip()
BING_SEARCH_API_KEY = os.getenv("BING_SEARCH_API_KEY", "").strip()

HEADERS = {
    "User-Agent": "VulnEnricher/1.0 (+https://cybernote.click)"
}

# 公式・高信頼とみなすドメイン（優先）
TRUST_SITES = [
    "advisory", "security", "support", "kb", "docs", "help",
    "cisco.com", "microsoft.com", "adobe.com", "oracle.com",
    "apple.com", "google.com", "cloud.google.com",
    "redhat.com", "debian.org", "ubuntu.com", "apache.org",
    "nvd.nist.gov", "cisa.gov", "jpcert.or.jp", "ipa.go.jp",
    "fortinet.com", "paloaltonetworks.com", "f5.com", "citrix.com",
    "gitlab.com", "github.com", "kernel.org"
]

# ────────────────────────────────
# 簡易ユーティリティ
# ────────────────────────────────
def _safe(x) -> str:
    return "" if x is None else str(x).strip()

def _is_trusted_url(url: str) -> bool:
    u = url.lower()
    return any(dom in u for dom in TRUST_SITES)

def _top_n_unique(seq: List[str], n: int) -> List[str]:
    out, seen = [], set()
    for s in seq:
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= n:
            break
    return out

def _fetch(url: str, timeout: int = 20) -> str:
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout)
        if r.ok and r.text:
            return r.text
    except Exception:
        pass
    return ""

def _strip_html_minimal(html_text: str) -> str:
    text = re.sub(r"(?is)<script.*?>.*?</script>", " ", html_text)
    text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()

# ────────────────────────────────
# 検索（SerpAPI / Bing）
# ────────────────────────────────
def _search_web(cve: str) -> List[str]:
    """検索APIで有力URLを集める。SerpAPI→Bingの順で利用。"""
    queries = [
        f'"{cve}" advisory',
        f'"{cve}" vendor advisory',
        f'"{cve}" exploit',
        f'"{cve}" security bulletin',
        f'"{cve}" patch release',
    ]
    urls: List[str] = []

    if SERPAPI_API_KEY:
        for q in queries:
            try:
                resp = requests.get(
                    "https://serpapi.com/search.json",
                    params={"engine": "google", "q": q, "api_key": SERPAPI_API_KEY, "num": "10"},
                    timeout=20,
                )
                if resp.ok:
                    data = resp.json() or {}
                    for item in (data.get("organic_results") or []):
                        u = _safe(item.get("link"))
                        if u:
                            urls.append(u)
            except Exception:
                continue

    if not urls and BING_SEARCH_API_KEY:
        for q in queries:
            try:
                resp = requests.get(
                    "https://api.bing.microsoft.com/v7.0/search",
                    headers={"Ocp-Apim-Subscription-Key": BING_SEARCH_API_KEY, **HEADERS},
                    params={"q": q, "count": "10", "textDecorations": "false"},
                    timeout=20,
                )
                if resp.ok:
                    data = resp.json() or {}
                    for item in (data.get("webPages", {}).get("value") or []):
                        u = _safe(item.get("url"))
                        if u:
                            urls.append(u)
            except Exception:
                continue

    urls_trusted = [u for u in urls if _is_trusted_url(u)]
    if urls_trusted:
        urls = urls_trusted + [u for u in urls if u not in urls_trusted]

    return _top_n_unique(urls, 20)

# ────────────────────────────────
# OpenAI 要約・抽出
# ────────────────────────────────
def _openai_summarize(cve: str, raw_blobs: List[str]) -> Dict:
    """OpenAIで本文要約・抽出を実施し、統合結果を返す。"""
    if not OPENAI_API_KEY:
        return {}

    joined = "\n\n---\n\n".join(blob[:4000] for blob in raw_blobs[:6])

    system = (
        "あなたはサイバーセキュリティの専門アナリストです。"
        "入力の生テキストからCVEの公式・信頼情報を統合し、"
        "日本語で分かりやすく正確に要約してください。"
        "必ず事実ベースのみで、推測は書かないこと。"
    )

    user = f"""
対象: {cve}
以下はウェブから収集した本文断片です（重複やノイズを含む可能性があります）。
これらを統合し、次のJSONスキーマに沿って日本語で返答してください。

【欲しいJSONキー】
- vendor: 例) Cisco
- product: 例) ASA、WordPress プラグイン名等（型番/モデル名でも可）
- summary_ja: 300〜500字で、非エンジニアも読める自然な日本語の概要
- exploited: 真偽値。CISA KEVや複数の信頼筋に悪用事実が明記/報道されていれば true
- top_links: 重要度の高い参考URL 上位3件（公式優先）
- title_ja: 40〜60字の日本語タイトル（ベンダ/製品名＋脆弱性の要点＋緊急度）
- body_md: 日本語Markdown本文。見出し、表、箇条書きを活用し、再現性のある対策を明記すること。
"""

    try:
        from openai import OpenAI
        client = OpenAI(api_key=OPENAI_API_KEY)
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0.2,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user + "\n\n本文:\n" + joined},
            ],
        )
        txt = resp.choices[0].message.content or ""
    except Exception:
        return {}

    out = {
        "vendor": "",
        "product": "",
        "summary_ja": "",
        "exploited": False,
        "top_links": [],
        "title_ja": "",
        "body_md": "",
    }

    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", txt, re.S | re.I)
    blob = m.group(1) if m else txt

    def _find_str(key):
        m = re.search(rf'"?{key}"?\s*:\s*"([^"]+)"', blob)
        return _safe(m.group(1)) if m else ""

    def _find_bool(key):
        m = re.search(rf'"?{key}"?\s*:\s*(true|false)', blob, re.I)
        if not m:
            return False
        return m.group(1).lower() == "true"

    def _find_links() -> List[str]:
        m = re.search(r'"?top_links"?\s*:\s*\[(.*?)\]', blob, re.S)
        if not m:
            return []
        inside = m.group(1)
        return _top_n_unique(re.findall(r'"(https?://[^"]+)"', inside), 3)

    out["vendor"] = _find_str("vendor")
    out["product"] = _find_str("product")
    out["summary_ja"] = _find_str("summary_ja")
    out["exploited"] = _find_bool("exploited")
    out["title_ja"] = _find_str("title_ja")
    out["body_md"] = _find_str("body_md")
    out["top_links"] = _find_links()

    return out

# ────────────────────────────────
# エントリポイント
# ────────────────────────────────
def enrich_cve_item(item: Dict) -> Dict:
    """
    入力: feeds.normalize_items が返す1件
    出力: item を追記・上書きして返す（vendor/product/summary/references/exploit_confirmed/title/body_markdown）
    """
    cve = _safe(item.get("cve"))
    if not cve:
        return item

    # 1) 検索
    urls = _search_web(cve)

    # 2) 本文抽出（超簡易）
    blobs: List[str] = []
    for u in urls:
        html_text = _fetch(u)
        if not html_text:
            continue
        text = _strip_html_minimal(html_text)
        if text:
            blobs.append(text)

    # 3) OpenAI で統合要約
    ai = _openai_summarize(cve, blobs)

    # 4) item に反映（空なら既存値は保持）
    if ai:
        if ai.get("vendor"):
            item["vendor"] = ai["vendor"]
        if ai.get("product"):
            item["product"] = ai["product"]
        if ai.get("summary_ja"):
            item["summary"] = ai["summary_ja"]
            item["description"] = ai["summary_ja"]
        if "exploited" in ai:
            item["exploit_confirmed"] = bool(ai["exploited"])

        # 参考リンク
        refs = []
        for u in ai.get("top_links", []):
            refs.append(("参考情報", u))
        if refs:
            item["references"] = refs

        # 記事タイトル/本文
        if ai.get("title_ja"):
            item["title_ja"] = ai["title_ja"]
        if ai.get("body_md"):
            item["body_md"] = ai["body_md"]

    return item
