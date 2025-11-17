import os
import requests
from typing import Dict, List

def _from_nvd_references(item: Dict) -> List[str]:
    """NVDの参照情報から公式アドバイザリURLを抽出"""
    refs = item.get("nvd_references") or []
    urls = []
    for r in refs:
        url = r.get("url")
        tags = [t.lower() for t in (r.get("tags") or [])]
        if not url:
            continue
        # 👇 括弧閉じ忘れを修正済み
        if any(t in tags for t in ["vendor advisory", "patch", "release notes", "product"]):
            urls.append(url)

    # 重複除去
    dedup = []
    seen = set()
    for u in urls:
        if u not in seen:
            dedup.append(u)
            seen.add(u)
    return dedup[:5]

def _bing_search(query: str, count: int = 3) -> List[str]:
    """Bing Search API（任意）を利用して公式URLを補完"""
    api_key = os.environ.get("BING_API_KEY")
    if not api_key:
        return []
    endpoint = "https://api.bing.microsoft.com/v7.0/search"
    try:
        r = requests.get(
            endpoint,
            headers={"Ocp-Apim-Subscription-Key": api_key},
            params={"q": query, "mkt": "ja-JP", "count": count, "responseFilter": "Webpages"},
            timeout=30
        )
        r.raise_for_status()
        js = r.json()
        web = (js.get("webPages") or {}).get("value") or []
        urls = []
        for w in web:
            u = w.get("url")
            if u:
                urls.append(u)
        return urls
    except Exception:
        return []

def _openai_guess_urls(cve: str, vendor: str, product: str) -> List[str]:
    """
    ChatGPTに「公式アドバイザリURL候補」を推定させる（NVDに情報がない場合の最終手段）
    """
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return []
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        prompt = (
            f"{cve} の『公式アドバイザリURL』候補を、ベンダードメインのものを優先して最大3件、URLのみで列挙してください。"
            f"ベンダ: {vendor or '不明'} / 製品: {product or '不明'}。"
        )
        rsp = client.chat.completions.create(
            model="gpt-5",  # GPT-5固定
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        text = rsp.choices[0].message.content.strip()
        urls = []
        for line in text.splitlines():
            line = line.strip("-•* ").strip()
            if line.startswith("http"):
                urls.append(line)
        return urls[:3]
    except Exception:
        return []

def pick_official_links(item: Dict) -> List[str]:
    """公式アドバイザリURLを段階的に探索して返す"""
    # 1️⃣ NVD参照（最優先）
    urls = _from_nvd_references(item)
    if urls:
        return urls

    # 2️⃣ Bing API（任意）
    cve     = item.get("cve") or ""
    vendor  = item.get("vendor") or ""
    product = item.get("product") or ""
    q = f'{cve} official advisory site:{vendor}.com' if vendor else f'{cve} official advisory'
    urls = _bing_search(q)
    if urls:
        return urls

    # 3️⃣ ChatGPT補助（最終手段）
    urls = _openai_guess_urls(cve, vendor, product)
    return urls
