#!/usr/bin/env python3
"""
Find Cryptobib citation keys from DBLP by paper title.
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
    "transactions on cryptographic hardware and embedded systems": "TCHES",
    "transactions on symmetric cryptology": "ToSC",
    "journal of cryptology": "JC",

    # Security conferences
    "ccs": "CCS",
    "acm conference on computer and communications security": "CCS",
    "acm ccs": "CCS",
    "acm conference on computer & communications security": "CCS",
    "acm conference on computer and comm. security": "CCS",
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

    # Regional / specialized crypto conferences
    "acisp": "ACISP",
    "africacrypt": "AFRICACRYPT",
    "acns": "ACNS",
    "asiaccs": "ASIACCS",
    "cans": "CANS",
    "cosade": "COSADE",
    "cqre": "CQRE",
    "ct-rsa": "RSA",
    "cryptographers track at the rsa conference": "RSA",
    "cic": "CiC",
    "iacr cic": "CiC",
    "iacr commun. cryptol.": "CiC",
    "iacr communications in cryptology": "CiC",
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
    "ndss symposium": "NDSS",
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

AUTHOR_PARTICLES = {
    "da", "de", "del", "della", "di", "do", "dos",
    "du", "la", "le", "van", "der", "den", "ter", "von",
}


# ----------------------------------------------------------------------
# HTTP / DBLP
# ----------------------------------------------------------------------

def http_get(url: str) -> str:
    req = urllib.request.Request(
        url, headers={"User-Agent": "cryptobib-key/0.1"}
    )
    with urllib.request.urlopen(req) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset)


def search_hits(title: str) -> list[dict]:
    query = urllib.parse.quote_plus(title)
    url = f"https://dblp.org/search/publ/api?q={query}&format=json&h={MAX_HITS}"
    data = json.loads(http_get(url))

    hits = data.get("result", {}).get("hits", {}).get("hit") or []
    if isinstance(hits, dict):
        hits = [hits]

    crypto_hits = []
    for h in hits:
        info = h.get("info", {})
        if not is_crypto_hit(info):
            continue
        crypto_hits.append(h)

    def is_eprint(h):
        info = h.get("info", {})
        venue = (
            info.get("venue")
            or info.get("journal")
            or info.get("booktitle")
            or ""
        )
        norm = normalize_venue(venue)
        return "eprint" in norm

    # Stable ordering:
    #   1. Non-ePrint first
    #   2. ePrint last
    crypto_hits.sort(key=lambda h: is_eprint(h))

    return crypto_hits


# ----------------------------------------------------------------------
# Venue filtering
# ----------------------------------------------------------------------

def normalize_venue(s: str) -> str:
    s = re.sub(r"[{}]", "", s)
    s = re.sub(r"\s+", " ", s)
    return s.lower().strip()


def is_crypto_hit(info: dict) -> bool:
    venue = (
        info.get("venue")
        or info.get("journal")
        or info.get("booktitle")
        or ""
    )
    if not venue:
        return False
    norm = normalize_venue(venue)
    return any(k in norm for k in CRYPTO_VENUES)


def venue_label(info: dict) -> str:
    # Pick venue from DBLP
    venue = info.get("venue") or info.get("journal") or info.get("booktitle") or ""
    norm = normalize_venue(venue)

    # 1. Absolute priority: ePrint
    if "eprint" in norm:
        return "EPRINT"
    
    # 2. High priority: Communications in Cryptology (CiC)
    # This must come before the "crypto" conference check to avoid false positives.
    if ("communic" in norm or "cic" in norm) and ("cryptol" in norm or "cryptog" in norm):
        return "CiC"

    # 3. Standard Whitelist check
    # Normalize whitelist keys and sort by length descending to match longest phrases first
    norm_keys = [(normalize_venue(k), v) for k, v in CRYPTO_VENUES.items()]
    norm_keys.sort(key=lambda kv: len(kv[0]), reverse=True)

    for k_norm, v in norm_keys:
        # Avoid "crypto" matching "cryptology" journals incorrectly
        if k_norm == "crypto":
            # Only match "crypto" if it's the specific conference name
            if "advances in cryptology" in norm and "crypto" in norm:
                return "C"
            continue 
            
        if k_norm in norm:
            return v

    # Fallback for other CiC variants
    if "cic" in norm:
        return "CiC"

    # Debug info if nothing matches
    print(f"DEBUG: venue='{venue}', norm='{norm}'", file=sys.stderr)
    raise ValueError(f"Venue not Cryptobib-legal: {venue}")


# ----------------------------------------------------------------------
# Split author strings safely, respecting braces
# ----------------------------------------------------------------------

def _split_on_spaces(value: str) -> list[str]:
    tokens, buf, depth = [], [], 0
    for c in value:
        if c == "{":
            depth += 1
        elif c == "}":
            depth = max(0, depth - 1)
        if c.isspace() and depth == 0:
            if buf:
                tokens.append("".join(buf))
                buf = []
        else:
            buf.append(c)
    if buf:
        tokens.append("".join(buf))
    return tokens


def split_authors(value: str) -> list[str]:
    value = re.sub(r"\s+", " ", value).strip()
    authors, buf, depth, i = [], [], 0, 0
    while i < len(value):
        if value[i] == "{":
            depth += 1
        elif value[i] == "}":
            depth = max(0, depth - 1)
        if depth == 0 and value[i:i+5].lower() == " and ":
            authors.append("".join(buf).strip())
            buf = []
            i += 5
            continue
        buf.append(value[i])
        i += 1
    if buf:
        authors.append("".join(buf).strip())
    return authors

# ----------------------------------------------------------------------
# Name formatting
# ----------------------------------------------------------------------

def format_author(name: str) -> str:
    """Format name as 'Last, First', handling particles and braces."""
    name = re.sub(r"\s+", " ", name).strip()
    if "," in name:
        return re.sub(r"\s*,\s*", ", ", name)

    parts = name.split()
    if len(parts) <= 1:
        return name

    idx = len(parts) - 1
    while idx > 0:
        cand = re.sub(r"[{}]", "", parts[idx - 1])
        if cand and cand[0].islower():
            idx -= 1
        else:
            break

    last = " ".join(parts[idx:])
    first = " ".join(parts[:idx])
    return f"{last}, {first}" if first else last

def ascii_normalize(s: str) -> str:
    """Normalize accents and diacritics to ASCII."""
    s = unicodedata.normalize('NFKD', s)
    return "".join(c for c in s if c.isascii())

# ----------------------------------------------------------------------
# Generate Cryptobib author label
# ----------------------------------------------------------------------

def author_label(authors: list[str]) -> str:
    """Generate Cryptobib author label from a list of author names."""
    lasts = []
    for a in authors:
        last = format_author(a).split(",", 1)[0]

        # remove braces, but keep letters inside
        last = last.replace("{", "").replace("}", "")

        # normalize diacritics
        last = ascii_normalize(last)

        # keep letters only
        last = "".join(c for c in last if c.isalpha())

        # fallback if empty
        if not last:
            last = "X"

        lasts.append(last)

    n = len(lasts)
    if n == 1:
        return lasts[0]
    elif n <= 3:
        return "".join(l[:3] for l in lasts)
    else:
        return "".join(l[0] for l in lasts[:6])


# ----------------------------------------------------------------------
# Cryptobib key
# ----------------------------------------------------------------------

def cryptobib_key(info: dict) -> str:
    authors_raw = info.get("authors", {}).get("author")
    if not authors_raw:
        raise ValueError("Missing authors")

    if isinstance(authors_raw, list):
        names = [a["text"] for a in authors_raw]
    else:
        names = [authors_raw["text"]]

    a_label = author_label(names)
    year = info.get("year")
    if not year:
        raise ValueError("Missing year")

    v_label = venue_label(info)
    return f"{v_label}:{a_label}{year[-2:]}"


# ----------------------------------------------------------------------
# UI
# ----------------------------------------------------------------------

def describe_hit(info: dict) -> str:
    venue = info.get("venue") or info.get("journal") or ""
    return f"{venue} {info.get('year', '')}: {info.get('title', '')}"


def choose_hit(hits: list[dict]) -> dict:
    if len(hits) == 1:
        return hits[0]

    descs = [describe_hit(h["info"]) for h in hits]

    def selector(stdscr):
        curses.curs_set(0)
        idx = 0
        while True:
            stdscr.clear()
            h, w = stdscr.getmaxyx()
            stdscr.addstr(0, 0, "Select Cryptobib entry:")
            for i, d in enumerate(descs):
                if i + 1 >= h:
                    break
                line = textwrap.shorten(d, w - 4, placeholder="...")
                attr = curses.A_REVERSE if i == idx else curses.A_NORMAL
                stdscr.addstr(i + 1, 0, ("> " if i == idx else "  ") + line, attr)
            k = stdscr.getch()
            if k in (curses.KEY_UP, ord("k")):
                idx = (idx - 1) % len(hits)
            elif k in (curses.KEY_DOWN, ord("j")):
                idx = (idx + 1) % len(hits)
            elif k in (10, 13):
                return hits[idx]
            elif k in (27, ord("q")):
                raise KeyboardInterrupt

    if sys.stdin.isatty() and sys.stdout.isatty():
        return curses.wrapper(selector)

    # fallback
    for i, d in enumerate(descs, 1):
        print(f"{i}. {d}")
    return hits[int(input("Select: ")) - 1]


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print('Usage: cryptobib_key.py "Paper Title"', file=sys.stderr)
        sys.exit(1)

    title = " ".join(sys.argv[1:])
    hits = search_hits(title)
    if not hits:
        print("No Cryptobib-valid entry found.", file=sys.stderr)
        sys.exit(1)

    chosen = choose_hit(hits)
    key = cryptobib_key(chosen["info"])
    print(key)


if __name__ == "__main__":
    main()