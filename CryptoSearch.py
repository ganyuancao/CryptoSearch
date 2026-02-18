#!/usr/bin/env python3
"""
Find Cryptobib citation keys from DBLP by paper title.
Includes venue debugging and "domain" (publication type) checks.
"""

import curses
import json
import re
import unicodedata
import sys
import textwrap
import urllib.parse
import urllib.request

MAX_HITS = 10

# ----------------------------------------------------------------------
# Cryptobib venue whitelist
# ----------------------------------------------------------------------

CRYPTO_VENUES = {
    # Major IACR conferences
    "crypto": "C",
    "eurocrypt": "EC",
    "asiacrypt": "AC",
    "tcc": "TCC",
    "ches": "CHES",
    "fse": "FSE",
    "pkc": "PKC",

    # IACR journals / archives
    "iacr cryptology eprint archive": "EPRINT",
    "cryptology eprint archive": "EPRINT",
    "transactions on cryptographic hardware and embedded systems": "TCHES",
    "tches": "TCHES",
    "iacr trans cryptogr hardw embed syst": "TCHES",
    "transactions on symmetric cryptology": "ToSC",
    "tosc": "ToSC",
    "iacr trans symmetric cryptol": "ToSC",
    "journal of cryptology": "JC",
    "j cryptol": "JC",
    "iacr communications in cryptology": "CiC",
    "iacr commun cryptol": "CiC",
    "cic": "CiC",

    # Security conferences
    "ccs": "CCS",
    "acm conference on computer and communications security": "CCS",
    "acm ccs": "CCS",
    "ndss": "NDSS",
    "ieee symposium on security and privacy": "SP",
    "ieee s&p": "SP",
    "usenix security symposium": "USENIX",
    "esorics": "ESORICS",
    "computer security foundations": "CSF",

    # Theory conferences
    "stoc": "STOC",
    "focs": "FOCS",
    "itcs": "ITCS",
    "soda": "SODA",
    "icalp": "ICALP",
    "podc": "PODC",
    "latin": "LATIN",

    # Regional / specialized
    "acisp": "ACISP",
    "africacrypt": "AFRICACRYPT",
    "acns": "ACNS",
    "asiaccs": "ASIACCS",
    "cans": "CANS",
    "cosade": "COSADE",
    "cqre": "CQRE",
    "ct-rsa": "RSA",
    "cryptographers track at the rsa conference": "RSA",
    "dcc": "DCC",
    "fc": "FC",
    "financial cryptography": "FC",
    "fcw": "FCW",
    "icics": "ICICS",
    "icisc": "ICISC",
    "icits": "ICITS",
    "ieee european symposium on security and privacy": "EUROSP",
    "ieee eurosp": "EUROSP",
    "ima international conference on cryptography and coding": "IMA",
    "indocrypt": "INDOCRYPT",
    "isc": "ISC",
    "itc": "ITC",
    "iwsec": "IWSEC",
    "latincrypt": "LC",
    "pairing": "PAIRING",
    "pets": "PETS",
    "privacy enhancing technologies symposium": "PETS",
    "popets": "PoPETS",
    "pqcrypto": "PQCRYPTO",
    "provsec": "PROVSEC",
    "sac": "SAC",
    "selected areas in cryptography": "SAC",
    "scn": "SCN",
    "trustbus": "TRUSTBUS",
    "vietcrypt": "VIETCRYPT",
    "wisa": "WISA",
}

SORTED_VENUE_KEYS = sorted(CRYPTO_VENUES.keys(), key=len, reverse=True)

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def normalize_venue(s: str) -> str:
    s = re.sub(r"[{}]", "", s)
    s = s.replace(".", "")
    return re.sub(r"\s+", " ", s).lower().strip()

def ascii_normalize(s: str) -> str:
    s = unicodedata.normalize('NFKD', s)
    return "".join(c for c in s if c.isascii())

def http_get(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "cryptobib-key/0.1"})
    with urllib.request.urlopen(req) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset)

# ----------------------------------------------------------------------
# Logic
# ----------------------------------------------------------------------

def venue_label(info: dict) -> str:
    """Map DBLP venue to Cryptobib label with debug reporting."""
    venue = info.get("venue") or info.get("journal") or info.get("booktitle") or ""
    norm = normalize_venue(venue)

    if not norm:
        raise ValueError("Venue field is empty in DBLP entry.")

    # 1. ePrint check
    if "eprint" in norm:
        return "EPRINT"
    
    # 2. Match against whitelist
    for key in SORTED_VENUE_KEYS:
        if key in norm or (len(norm) > 3 and norm == key):
            return CRYPTO_VENUES[key]

    # --- Debugging Point ---
    # This helps you see exactly why a venue didn't match
    print(f"\n[DEBUG] Domain/Type: {info.get('type')}", file=sys.stderr)
    print(f"[DEBUG] Raw Venue:   '{venue}'", file=sys.stderr)
    print(f"[DEBUG] Norm Venue:  '{norm}'", file=sys.stderr)
    raise ValueError(f"Venue not in Cryptobib whitelist: {venue}")

def format_author(name: str) -> str:
    name = re.sub(r"\s+\d+$", "", name).strip()
    name = re.sub(r"\s+", " ", name)
    if "," in name: return re.sub(r"\s*,\s*", ", ", name)

    parts = name.split()
    if len(parts) <= 1: return name

    idx = len(parts) - 1
    while idx > 0:
        cand = parts[idx - 1].replace("{", "").replace("}", "")
        if cand and cand[0].islower(): idx -= 1
        else: break

    last, first = " ".join(parts[idx:]), " ".join(parts[:idx])
    return f"{last}, {first}" if first else last

def author_label(authors: list[str]) -> str:
    lasts = []
    for a in authors:
        last = format_author(a).split(",", 1)[0]
        last = ascii_normalize(last.replace("{", "").replace("}", ""))
        last = "".join(c for c in last if c.isalpha()) or "X"
        lasts.append(last)

    n = len(lasts)
    if n == 1: return lasts[0]
    if n <= 3: return "".join(l[:3] for l in lasts)
    return "".join(l[0] for l in lasts[:6])

def cryptobib_key(info: dict) -> str:
    authors_raw = info.get("authors", {}).get("author")
    if not authors_raw: raise ValueError("Missing authors")

    names = [a["text"] for a in (authors_raw if isinstance(authors_raw, list) else [authors_raw])]
    year = info.get("year")
    if not year: raise ValueError("Missing year")

    return f"{venue_label(info)}:{author_label(names)}{year[-2:]}"

# ----------------------------------------------------------------------
# Search & UI
# ----------------------------------------------------------------------

def search_hits(title: str) -> list[dict]:
    query = urllib.parse.quote_plus(title)
    url = f"https://dblp.org/search/publ/api?q={query}&format=json&h={MAX_HITS}"
    try:
        data = json.loads(http_get(url))
    except Exception as e:
        print(f"Network Error: {e}", file=sys.stderr)
        return []

    hits = data.get("result", {}).get("hits", {}).get("hit") or []
    if isinstance(hits, dict): hits = [hits]

    # Pre-filter for crypto relevance to save time
    crypto_hits = []
    for h in hits:
        info = h.get("info", {})
        venue = info.get("venue") or info.get("journal") or info.get("booktitle") or ""
        if any(k in normalize_venue(venue) for k in CRYPTO_VENUES):
            crypto_hits.append(h)

    # Sort: Proceedings (Non-ePrint) first
    crypto_hits.sort(key=lambda h: "eprint" in normalize_venue(h['info'].get('venue', '')))
    return crypto_hits

def describe_hit(info: dict) -> str:
    """Helper to format the selection line with 'domain' (type) info."""
    v = info.get("venue") or info.get("journal") or "Unknown Venue"
    y = info.get("year", "????")
    t = info.get("title", "No Title")
    d = info.get("type", "Misc") # This is the "domain=" check
    return f" {v} ({y}): {t}"

def choose_hit(hits: list[dict]) -> dict:
    if len(hits) == 1:
        return hits[0]

    def selector(stdscr):
        curses.curs_set(0)
        idx = 0
        while True:
            stdscr.clear()
            h, w = stdscr.getmaxyx()
            stdscr.addstr(0, 0, "Select Entry (Arrows to move, Enter to select, 'q' to quit):", curses.A_BOLD)
            
            for i, hit in enumerate(hits):
                if i + 1 >= h: break
                line = textwrap.shorten(describe_hit(hit["info"]), w - 4, placeholder="...")
                attr = curses.A_REVERSE if i == idx else curses.A_NORMAL
                stdscr.addstr(i + 1, 0, ("> " if i == idx else "  ") + line, attr)
            
            k = stdscr.getch()
            if k in (curses.KEY_UP, ord("k")): idx = (idx - 1) % len(hits)
            elif k in (curses.KEY_DOWN, ord("j")): idx = (idx + 1) % len(hits)
            elif k in (10, 13): return hits[idx]
            elif k in (27, ord("q")): raise KeyboardInterrupt

    if sys.stdin.isatty():
        return curses.wrapper(selector)
    
    for i, h in enumerate(hits, 1):
        print(f"{i}. {describe_hit(h['info'])}")
    return hits[int(input("Select number: ")) - 1]

def main():
    if len(sys.argv) < 2:
        print('Usage: cryptobib_key.py "Paper Title"', file=sys.stderr)
        sys.exit(1)

    hits = search_hits(" ".join(sys.argv[1:]))
    if not hits:
        print("No Cryptobib-valid entries found on DBLP.", file=sys.stderr)
        sys.exit(1)

    try:
        chosen = choose_hit(hits)
        key = cryptobib_key(chosen['info'])
        print(f"\n{key}\n")
    except ValueError as ve:
        print(f"\n[ERROR] {ve}", file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, SystemExit):
        print("\nOperation cancelled.")
        sys.exit(0)

if __name__ == "__main__":
    main()