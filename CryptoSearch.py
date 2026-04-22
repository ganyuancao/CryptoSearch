#!/usr/bin/env python3
"""
Find Cryptobib citation keys from DBLP by paper title.
Outputs: Cryptobib Key followed by Full Human-Readable Citation (with et al. support).
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
    "Theory of Cryptography Conference": "TCC",
    "ches": "CHES",
    "Conference on Cryptographic Hardware and Embedded Systems": "CHES",
    "fse": "FSE",
    "Fast Software Encryption": "FSE",
    "pkc": "PKC",
    "Public Key Cryptography": "PKC",

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
# Logic for Citations
# ----------------------------------------------------------------------

def clean_name(name: str) -> str:
    """Removes DBLP digits like 'John Doe 0001' -> 'John Doe'."""
    return re.sub(r"\s+\d+$", "", name).strip()

def format_author_list(authors: list[str]) -> str:
    """Formats names into 'A, B, and C' style, or 'A et al.' for > 3 authors."""
    names = [clean_name(a) for a in authors]
    if not names: return "Unknown Author"
    
    # Use et al. for more than 3 authors
    if len(names) > 3:
        return f"{names[0]} et al"
    
    if len(names) == 1: return names[0]
    if len(names) == 2: return f"{names[0]} and {names[1]}"
    return ", ".join(names[:-1]) + f", and {names[-1]}"

def build_full_citation(info: dict) -> str:
    """Constructs: Authors. 'Title'. doi: XYZ or link: URL."""
    # Authors
    authors_raw = info.get("authors", {}).get("author")
    author_names = [a["text"] for a in (authors_raw if isinstance(authors_raw, list) else [authors_raw])] if authors_raw else []
    author_str = format_author_list(author_names)

    # Title
    title = info.get("title", "No Title").strip(".")
    
    # DOI or Link
    doi = info.get("doi")
    link = info.get("ee") 
    
    if doi:
        ref = f"DOI: {doi}"
    elif link:
        ref = f"URL: {link}"
    else:
        ref = ""

    return f"{author_str}. “{title}”. {ref}".strip()

# ----------------------------------------------------------------------
# Logic for Cryptobib Key
# ----------------------------------------------------------------------

def venue_label(info: dict) -> str:
    def is_generic(s: str) -> bool:
        return "advances in cryptology" in normalize_venue(s)

    # Prefer more precise fields, but skip generic ones if possible
    candidates = [
        info.get("booktitle"),
        info.get("journal"),
        info.get("venue"),
    ]

    venue = ""
    for c in candidates:
        if c and not is_generic(c):
            venue = c
            break

    # fallback if everything was generic
    if not venue:
        for c in candidates:
            if c:
                venue = c
                break

    norm = normalize_venue(venue)
    if not norm:
        raise ValueError("Venue field is empty.")

    if "eprint" in norm:
        return "EPRINT"

    # --- Strong signals first (avoid crypto swallowing others) ---
    if "public key cryptography" in norm or "pkc" in norm:
        return "PKC"
    if "eurocrypt" in norm:
        return "EC"
    if "asiacrypt" in norm:
        return "AC"

    # --- Original matching (but delay generic "crypto") ---
    for key in SORTED_VENUE_KEYS:
        if key == "crypto":
            continue
        if key in norm or (len(norm) > 3 and norm == key):
            return CRYPTO_VENUES[key]

    # --- Handle CRYPTO last ---
    if "crypto" in norm:
        return "C"

    raise ValueError(f"Venue not in whitelist: {venue}")

def is_initial(s: str) -> bool:
    """True if string is an initial like 'J' or 'J.'"""
    clean = s.replace(".", "")
    return len(clean) == 1

def extract_last_name_parts(author_entry: dict) -> tuple[str, str]:
    """
    Intelligently identifies surnames. 
    Handles:
    - Spanish double surnames: 'Manterola Ayala' -> ('', 'Manterola Ayala')
    - Middle initials: 'Daniel J. Bernstein' -> ('', 'Bernstein')
    - Particles: 'von Gleissenthall' -> ('von', 'Gleissenthall')
    """
    if "family" in author_entry:
        full_surname = author_entry["family"]
    else:
        name = clean_name(author_entry.get("text", ""))
        parts = name.split()
        if not parts: return "", "X"
        if len(parts) == 1: return "", parts[0]

        particles = {"von", "van", "de", "del", "der", "da", "di", "y"}
        
        # 1. Check if the second-to-last word is a particle (von, de, y)
        if parts[-2].lower() in particles:
            # Check if there's an even earlier particle (e.g., 'de la Cruz')
            if len(parts) > 3 and parts[-3].lower() in particles:
                full_surname = " ".join(parts[-3:])
            else:
                full_surname = " ".join(parts[-2:])
        
        # 2. Check if the second-to-last word is an INITIAL (Daniel J. Bernstein)
        elif is_initial(parts[-2]):
            full_surname = parts[-1]
            
        # 3. Compound/Spanish Case (Irati Manterola Ayala)
        # If there are 3+ words and the middle isn't an initial, assume double surname.
        elif len(parts) >= 3:
            full_surname = " ".join(parts[-2:])
            
        # 4. Standard Case (Michael Backes)
        else:
            full_surname = parts[-1]

    # Split into (particle, base) for the Key rules
    particles = {"von", "van", "de", "del", "der", "da", "di", "y"}
    s_parts = full_surname.split()
    
    if len(s_parts) > 1 and s_parts[0].lower() in particles:
        return s_parts[0].lower(), " ".join(s_parts[1:])
    return "", full_surname

def author_label(author_entries: list[dict]) -> str:
    n = len(author_entries)
    processed = [extract_last_name_parts(a) for a in author_entries]
    
    # Single Author: Use full normalized surname
    if n == 1:
        p, last = processed[0]
        full = (p + last) if p else last
        return "".join(c for c in ascii_normalize(full) if c.isalpha())

    # 2 or 3 Authors: 3-character chunks
    if n <= 3:
        label = ""
        for particle, surname in processed:
            # For "Manterola Ayala", surname_clean is "ManterolaAyala"
            surname_clean = "".join(c for c in ascii_normalize(surname) if c.isalpha())
            if particle:
                # Rule: v + St = vSt
                label += particle[0].lower() + surname_clean[:2]
            else:
                # Rule: ManterolaAyala -> Man
                label += surname_clean[:3]
        return label

    # 4+ Authors: 1-character initials
    label = ""
    for _, surname in processed[:6]:
        surname_clean = "".join(c for c in ascii_normalize(surname) if c.isalpha())
        if surname_clean:
            label += surname_clean[0]
    return label


def cryptobib_key(info: dict) -> str:
    authors_raw = info.get("authors", {}).get("author")
    if not authors_raw:
        raise ValueError("Missing authors")

    author_entries = (
        authors_raw if isinstance(authors_raw, list)
        else [authors_raw]
    )

    year = info.get("year")
    if not year:
        raise ValueError("Missing year")

    return f"{venue_label(info)}:{author_label(author_entries)}{year[-2:]}"


def resolve_year_collision(base_key: str, info: dict) -> str:
    """
    Only add suffix (a, b, c, ...) if multiple distinct papers
    would generate the exact same base_key.
    """

    year = info.get("year")
    if not year:
        return base_key

    authors_raw = info.get("authors", {}).get("author")
    if not authors_raw:
        return base_key

    author_entries = authors_raw if isinstance(authors_raw, list) else [authors_raw]
    _, first_last = extract_last_name_parts(author_entries[0])
    first_last = ascii_normalize(first_last)

    # Search broadly by first author + year
    query = urllib.parse.quote_plus(f"{first_last} {year}")
    url = f"https://dblp.org/search/publ/api?q={query}&format=json&h=200"

    try:
        data = json.loads(http_get(url))
    except:
        return base_key

    hits = data.get("result", {}).get("hits", {}).get("hit") or []
    if isinstance(hits, dict):
        hits = [hits]

    # Collect papers that produce the SAME base key
    same_key_papers = []

    for h in hits:
        i = h.get("info", {})
        try:
            if cryptobib_key(i) == base_key:
                same_key_papers.append(i)
        except:
            continue

    if len(same_key_papers) <= 1:
        return base_key

    # Preserve DBLP ordering
    for idx, paper in enumerate(same_key_papers):
        if paper.get("doi") == info.get("doi"):
            return base_key + chr(ord('a') + idx)
        if paper.get("title") == info.get("title"):
            return base_key + chr(ord('a') + idx)

    return base_key

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
    crypto_hits = []
    for h in hits:
        info = h.get("info", {})
        venue = info.get("venue") or info.get("journal") or info.get("booktitle") or ""
        if any(k in normalize_venue(venue) for k in CRYPTO_VENUES):
            crypto_hits.append(h)
    crypto_hits.sort(key=lambda h: "eprint" in normalize_venue(h['info'].get('venue', '')))
    return crypto_hits

def describe_hit(info: dict) -> str:
    v = info.get("venue") or info.get("journal") or "Unknown Venue"
    y = info.get("year", "????")
    t = info.get("title", "No Title")
    return f" {v} ({y}): {t}"

def choose_hit(hits: list[dict]) -> dict:
    if len(hits) == 1: return hits[0]
    def selector(stdscr):
        curses.curs_set(0)
        idx = 0
        while True:
            stdscr.clear()
            h, w = stdscr.getmaxyx()
            stdscr.addstr(0, 0, "Select Entry (Arrows, Enter to select, 'q' to quit):", curses.A_BOLD)
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
    if sys.stdin.isatty(): return curses.wrapper(selector)
    for i, h in enumerate(hits, 1): print(f"{i}. {describe_hit(h['info'])}")
    return hits[int(input("Select number: ")) - 1]



# ----------------------------------------------------------------------
# Main 
# ----------------------------------------------------------------------
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
        info = chosen['info']
        
        base = cryptobib_key(info)
        key = resolve_year_collision(base, info)
        citation = build_full_citation(info)
        
        print(f"\n[{key}]\n")
        print(f"{citation}\n")
        
    except ValueError as ve:
        print(f"\n[ERROR] {ve}", file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, SystemExit):
        print("\nOperation cancelled.")
        sys.exit(0)

if __name__ == "__main__":
    main()