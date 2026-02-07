#!/usr/bin/env python3
"""
Find Cryptobib citation keys from DBLP by paper title.
"""

import curses
import json
import re
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
    return [h for h in hits if is_crypto_hit(h.get("info", {}))]


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
    venue = (
        info.get("venue")
        or info.get("journal")
        or info.get("booktitle")
        or ""
    )
    norm = normalize_venue(venue)
    for k, v in CRYPTO_VENUES.items():
        if k in norm:
            return v
    raise ValueError("Venue not Cryptobib-legal")


# ----------------------------------------------------------------------
# Author parsing
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


def format_author(name: str) -> str:
    name = re.sub(r"\s+", " ", name).strip()
    if "," in name:
        return re.sub(r"\s*,\s*", ", ", name)
    parts = _split_on_spaces(name)
    if len(parts) <= 1:
        return name
    idx = len(parts) - 1
    while idx > 0:
        cand = re.sub(r"[{}]", "", parts[idx - 1])
        if cand and (cand[0].islower() or cand.lower() in AUTHOR_PARTICLES):
            idx -= 1
        else:
            break
    last = " ".join(parts[idx:])
    first = " ".join(parts[:idx])
    return f"{last}, {first}" if first else last


def author_label(authors: list[str]) -> str:
    lasts = []
    for a in authors:
        last = format_author(a).split(",", 1)[0]
        last = re.sub(r"[{}\-]", "", last)
        lasts.append(last)

    if len(lasts) == 1:
        return lasts[0]
    if len(lasts) <= 3:
        return "".join(n[:3] for n in lasts)
    return "".join(n[0] for n in lasts[:6])


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