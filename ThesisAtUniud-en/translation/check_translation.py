#!/usr/bin/env python3
"""Deterministic IT->EN translation check for the thesis.

For each Italian source file and its English counterpart (same relative path),
compares the language-independent LaTeX skeleton and reports every mismatch.
Usage: check_translation.py [relative/path.tex ...]   (default: all files)
Exit code 1 if any ERROR is reported.
"""
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC, DST = ROOT / "ThesisAtUniud", ROOT / "ThesisAtUniud-en"
GLOSSARY = DST / "translation" / "glossary.tsv"
FILES = ["thesis_Verrengia.tex", "appendices/a_appendice.tex", "thud.bib"] + sorted(
    f"chapters/{p.name}" for p in (SRC / "chapters").glob("*.tex") if p.name != "Bozze.tex"
)

CODE_ENVS = r"lstlisting|verbatim"
ITALIAN = re.compile(
    r"\b(il|lo|gli|della|delle|dello|degli|nel|nella|nei|che|per|non|una|sono|questo|questa|"
    r"anche|ogni|quindi|perché|perche|viene|essere|come|dove|quando|cioè|poi|già|più)\b"
)


def strip_comments(t):
    return re.sub(r"(?<!\\)%.*", "", t)


def code_blocks(t):
    return re.findall(rf"\\begin\{{({CODE_ENVS})\}}(?:\[[^\]]*\])?\n(.*?)\\end\{{\1\}}", t, re.S)


def prose(t):
    """Text with comments, code blocks, and anything after \\end{document} removed."""
    t = t.split("\\end{document}")[0]
    t = re.sub(rf"\\begin\{{({CODE_ENVS})\}}.*?\\end\{{\1\}}", "", t, flags=re.S)
    return strip_comments(t)


def skeleton(t):
    p = prose(t)
    keys = lambda pat: Counter(k.strip() for g in re.findall(pat, p) for k in g.split(","))
    return {
        "labels": keys(r"\\label\{([^}]*)\}"),
        "refs": keys(r"\\(?:auto|page|c|C|eq)?ref\{([^}]*)\}"),
        "cites": keys(r"\\cite[tp]?\*?(?:\[[^\]]*\])?\{([^}]*)\}"),
        "envs": [m for m in re.findall(r"\\(begin|end)\{([^}]*)\}", strip_comments(t))],
        "sections": re.findall(r"\\(part|chapter|section|subsection|subsubsection|paragraph)\*?(?=[{\[])", p),
        "inputs": re.findall(r"\\(?:input|include|includegraphics)(?:\[[^\]]*\])?\{([^}]*)\}", p),
        "urls": Counter(re.findall(r"\\(?:url|href)\{([^}]*)\}", p)),
        # \mbox/\text inside math is human-language text, so it's allowed to change
        # and Italian decimal commas ({,}) legitimately become decimal points
        "math": Counter(
            re.sub(r"\\(?:mbox|text)\{[^}]*\}", r"\\mbox{}", m).replace("{,}", ".")
            for m in re.findall(r"(?<!\\)\$[^$]+\$", p)
        ),
        "items": len(re.findall(r"\\item\b", p)),
        "code": [b for _, b in code_blocks(t)],
    }


def check(rel, glossary):
    s_t, d_path = (SRC / rel).read_text(), DST / rel
    if not d_path.exists():
        return [("ERROR", "missing translation")]
    d_t = d_path.read_text()
    # the dedication is already in English in the source
    if s_t == d_t and rel not in ("thud.bib", "chapters/00_dedica.tex"):
        return [("ERROR", "file identical to source (untranslated)")]
    out, s, d = [], skeleton(s_t), skeleton(d_t)
    for k in ("labels", "refs", "cites", "urls", "math"):
        if s[k] != d[k]:
            out.append(("ERROR", f"{k}: only-IT={dict(s[k] - d[k])} only-EN={dict(d[k] - s[k])}"))
    for k in ("envs", "sections", "inputs", "items"):
        if s[k] != d[k]:
            out.append(("ERROR", f"{k} differ: IT={s[k] if k != 'envs' else len(s[k])} EN={d[k] if k != 'envs' else len(d[k])}"))
    if len(s["code"]) != len(d["code"]):
        out.append(("ERROR", f"code block count {len(s['code'])} -> {len(d['code'])}"))
    else:
        for i, (a, b) in enumerate(zip(s["code"], d["code"])):
            if a != b:
                out.append(("WARN", f"code block #{i + 1} body changed (ok only if it translated Italian comments)"))
    if "\u2014" in prose(d_t) or re.search(r"(?<!-)---(?!-)", prose(d_t)):
        out.append(("ERROR", "em dash in English text (style rule: no em dashes)"))
    ratio = len(prose(d_t)) / max(1, len(prose(s_t)))
    if not 0.75 <= ratio <= 1.15:
        out.append(("WARN", f"prose length ratio EN/IT = {ratio:.2f} (possible omission or padding)"))
    for n, line in enumerate(prose(d_t).splitlines(), 1):
        hits = set(ITALIAN.findall(re.sub(r"\\[a-zA-Z]+|\{[^}]*\}", " ", line).lower()))
        if len(hits) >= 2:
            out.append(("WARN", f"possible Italian residue (prose line {n}): {sorted(hits)}"))
    s_low, d_low = prose(s_t).lower(), prose(d_t).lower()
    for it, en in glossary:
        if re.search(rf"(?<!\w){re.escape(it.lower())}(?!\w)", s_low) and en.lower() not in d_low:
            out.append(("WARN", f"glossary: '{it}' in source but '{en}' not in translation"))
    return out


def main():
    glossary = []
    if GLOSSARY.exists():
        for row in GLOSSARY.read_text().splitlines()[1:]:
            cols = row.split("\t")
            if len(cols) >= 2 and not row.startswith("#") and cols[0] and cols[1]:
                glossary.append((cols[0], cols[1]))
    errors = 0
    for rel in sys.argv[1:] or FILES:
        issues = check(rel, glossary)
        errors += sum(lvl == "ERROR" for lvl, _ in issues)
        print(f"== {rel}: {'OK' if not issues else f'{len(issues)} issue(s)'}")
        for lvl, msg in issues:
            print(f"  {lvl}: {msg}")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
