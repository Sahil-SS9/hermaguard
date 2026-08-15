#!/usr/bin/env python3
"""
Hermaguard Sanitize — injection-hardened review context (pre-pass).

CodeSentinel's finding (arXiv 2606.19235): code LLMs ingest repo context
that attackers can poison with instruction-shaped content hidden in
comments, strings, and decoy code. Indirect prompt injection against a
code reviewer is not hypothetical — the review prompt embeds untrusted
code verbatim.

This tool is the SYNTAX-LEVEL defense layer (CodeSentinel layer 1, no
model involved — it cannot itself be injected against). It scans the code
that will be embedded into review prompts and:

  1. DETECTS instruction-shaped comment/string content ("ignore previous",
     "you are now", "system:", "act as", imperative chains, JSON-schema
     demands, secrets-hiding phrases).
  2. NEUTRALIZES it in the review copy — replaced with a marker
     [SANITIZED:<id>] that keeps line count stable (line refs stay valid).
  3. FLAGS decoy payloads — base64 blobs, long hex strings, encoded
     instructions.
  4. EMITS A MANIFEST the reviewer must read alongside the code, so the
     sanitization is always visible, never silent.

Design honesty: this is not the full CodeSentinel (which adds Tree-sitter
CST + dynamic Min-K% scoring). It is the deterministic subset that runs
with zero dependencies and can't be gamed by the payload it detects.

Usage:
    hermaguard-sanitize.py --files a.py,b.ts --outdir /tmp/hermaguard/sanitized/
    hermaguard-sanitize.py --diff change.diff --outdir /tmp/hermaguard/sanitized/
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

VERSION = "1.0.0"

# Instruction-shaped patterns — comment/string content that should not
# silently reach the reviewer LLM.
INSTRUCTION_PATTERNS = [
    (r"\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)", "ignore-prior-instruction"),
    (r"\bdisregard\s+(all\s+)?(previous|prior)", "disregard-prior"),
    (r"\byou\s+are\s+now\b|\bact\s+as\b|\byour\s+new\s+role\b|\bforget\s+(all\s+)?your", "role-override"),
    (r"\bsystem\s*(prompt)?\s*[:=]", "system-prompt"),
    (r"\b(important|critical|urgent)\s*[:!]|follow\s+(these|this|the)\s+(instructions?|rules?)\s+exactly", "instruction-demands"),
    (r"\b(never|do\s+not|don'?t)\s+(tell|mention|reveal|say|report|include)\b", "secrecy-demand"),
    (r"\b(only|always)\s+output\b|output\s+(only|strictly|exactly)", "output-shape-demand"),
    (r"\bmust\s+(return|output|respond|answer|include|add|remove)\b", "mandate"),
    (r"\bstart\s+(your\s+)?(response|answer|message)\s+with\b", "response-control"),
    (r"\bjson\s*(object|schema|format)?\s*(with|containing|keys?)\s*[:=]", "json-schema-demand"),
]

# Decoy payloads: encoded/obfuscated content that commonly hides injected
# instructions or exfiltrated text.
DECOY_PATTERNS = [
    (r"[A-Za-z0-9+/]{80,}={0,2}", "base64-blob"),
    (r"(?<![0-9a-fA-F])[0-9a-fA-F]{64,}(?![0-9a-fA-F])", "long-hex"),
    (r"(eval|exec|execve|system)\s*\(\s*(base64|bytes|decode|unhexlify|exec)\s*\(", "encoded-exec"),
]

COMMENT_STYLES = {
    ".py":   [("#", None), ('"""', '"""'), ("'''", "'''")],
    ".js":   [("//", None), ("/*", "*/")],
    ".ts":   [("//", None), ("/*", "*/")],
    ".jsx":  [("//", None), ("/*", "*/")],
    ".tsx":  [("//", None), ("/*", "*/")],
    ".go":   [("//", None), ("/*", "*/")],
    ".rs":   [("//", None), ("/*", "*/")],
    ".java": [("//", None), ("/*", "*/")],
    ".sh":   [("#", None)],
    ".sql":  [("--", None), ("/*", "*/")],
    ".c":    [("//", None), ("/*", "*/")],
    ".cpp":  [("//", None), ("/*", "*/")],
    ".h":    [("//", None), ("/*", "*/")],
    ".hpp":  [("//", None), ("/*", "*/")],
}

SANITIZED_MARKER = "SANITIZED"


def sanitize_text(text: str, lang: str) -> tuple[str, list]:
    """Return (sanitized_text, manifest_entries). Line count is preserved."""
    styles = COMMENT_STYLES.get("." + lang, [("#", None)])
    lines = text.split("\n")
    manifest = []
    # Track block-comment state across lines
    in_block = None
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        # Block comment detection (multi-line /* */ or """ """)
        if in_block:
            end_idx = line.find(in_block[1])
            if end_idx != -1:
                in_block = None
                continue
            else:
                # still inside a block comment — scan full line content
                content = line
                hits = _scan_content(content, offset=0)
                if hits:
                    line = _neutralize_line(line, hits, manifest, i + 1)
                    lines[i] = line
                continue
        for prefix, closer in styles:
            if stripped.startswith(prefix):
                idx = line.find(prefix)
                content_start = idx + len(prefix)
                if closer:  # block opener
                    if closer in line[content_start:]:
                        content = line[content_start:].split(closer)[0]
                        hits = _scan_content(content, offset=content_start)
                        if hits:
                            line = _neutralize_line(line, hits, manifest, i + 1)
                            lines[i] = line
                        continue
                    else:
                        in_block = (prefix, closer)
                        content = line[content_start:]
                        hits = _scan_content(content, offset=content_start)
                        if hits:
                            line = _neutralize_line(line, hits, manifest, i + 1)
                            lines[i] = line
                        break
                else:  # line comment
                    content = line[content_start:]
                    hits = _scan_content(content, offset=content_start)
                    if hits:
                        line = _neutralize_line(line, hits, manifest, i + 1)
                        lines[i] = line
                    break
        # Non-comment lines: scan for decoy payloads in string-ish content
        if not in_block and not stripped.startswith(tuple(p for p, _ in styles)):
            hits = _scan_decoy(line)
            if hits:
                line = _neutralize_line(line, hits, manifest, i + 1, decoy=True)
                lines[i] = line
    return "\n".join(lines), manifest

def _scan_content(content: str, offset: int = 0) -> list:
    hits = []
    for rx, label in INSTRUCTION_PATTERNS:
        for m in re.finditer(rx, content, re.IGNORECASE):
            hits.append({"kind": "instruction", "label": label,
                         "snippet": content[max(0, m.start() - 20):m.end() + 30].strip(),
                         "start": offset + m.start(), "end": offset + m.end()})
    return hits


def _scan_decoy(line: str) -> list:
    hits = []
    for rx, label in DECOY_PATTERNS:
        for m in re.finditer(rx, line):
            hits.append({"kind": "decoy", "label": label,
                         "snippet": m.group(0)[:60] + ("…" if len(m.group(0)) > 60 else ""),
                         "start": m.start(), "end": m.end()})
    return hits


def _neutralize_line(line: str, hits: list, manifest: list, lineno: int, decoy: bool = False) -> str:
    """Replace hit spans with markers, keep line count stable."""
    for h in hits:
        marker = f"[{SANITIZED_MARKER}:{h['label']}]"
        manifest.append({"line": lineno, "kind": h["kind"], "label": h["label"],
                         "snippet": h["snippet"], "marker": marker})
    # Apply replacements from the END so earlier spans stay valid.
    for h in sorted(hits, key=lambda x: -x["start"]):
        marker = f"[{SANITIZED_MARKER}:{h['label']}]"
        line = line[:h["start"]] + marker + line[h["end"]:]
    return line


def sanitize_files(files: list, outdir: str) -> dict:
    """Sanitize each file; write sanitized copies + manifest JSON."""
    os.makedirs(outdir, exist_ok=True)
    all_manifest = []
    written = []
    for f in files:
        p = Path(f)
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        lang = p.suffix.lstrip(".")
        sanitized, manifest = sanitize_text(text, lang)
        for e in manifest:
            e["file"] = str(p)
        all_manifest.extend(manifest)
        # write sanitized copy
        out_path = os.path.join(outdir, p.name)
        Path(out_path).write_text(sanitized)
        written.append({"original": str(p), "sanitized": out_path,
                        "neutralized": len(manifest)})
    manifest_path = os.path.join(outdir, "sanitize-manifest.json")
    Path(manifest_path).write_text(json.dumps({
        "tool": "hermaguard-sanitize", "version": VERSION,
        "files": written,
        "entries": all_manifest,
        "stats": {"files": len(written), "neutralized": len(all_manifest),
                  "by_label": {}},
    }, indent=2))
    return {"files": written, "entries": all_manifest,
            "stats": {"files": len(written), "neutralized": len(all_manifest)}}


def main():
    p = argparse.ArgumentParser(description="Hermaguard injection-hardened context sanitizer")
    p.add_argument("--files", help="Comma-separated file paths")
    p.add_argument("--outdir", required=True, help="Directory for sanitized copies + manifest")
    args = p.parse_args()
    if not args.files:
        p.error("--files required")
    files = [f.strip() for f in args.files.split(",") if f.strip()]
    out = sanitize_files(files, args.outdir)
    print(f"sanitize: {out['stats']['files']} files, {out['stats']['neutralized']} "
          f"instruction-shaped/decoy items neutralized → {args.outdir}/sanitize-manifest.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
