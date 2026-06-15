#!/usr/bin/env python3
"""
AGENTS.md Linter — Scores instruction files based on evidence from research.
A regex keyword/structure heuristic inspired by (not derived from) the
Instructions-as-Code criteria for what makes instruction files effective for
AI coding agents. A high score is necessary, not sufficient: it rewards
presence of the right signals, it does not verify they are correct.

Criteria (from research):
  1. Specificity — concrete rules, not vague guidance
  2. Project conventions — naming, file structure, patterns
  3. Test guidance — how to run tests, what coverage means
  4. Component navigation — which files do what, dependency map
  5. Stack details — versions, tools, configuration
  6. Anti-patterns — what NOT to do, common mistakes
  7. Scope boundaries — what the agent should and shouldn't touch

Usage:
    python3 agentsmd-lint.py /path/to/CLAUDE.md
    python3 agentsmd-lint.py --dir /path/to/project  (finds CLAUDE.md/AGENTS.md)
"""

import argparse
import os
import re
import sys
from datetime import datetime

VERSION = "1.0.0"


def find_instruction_files(directory: str) -> list:
    """Find CLAUDE.md, AGENTS.md, or .cursorrules files."""
    candidates = ["CLAUDE.md", "AGENTS.md", ".cursorrules", ".claude/CLAUDE.md", ".github/AGENTS.md"]
    found = []
    for c in candidates:
        path = os.path.join(directory, c)
        if os.path.isfile(path):
            found.append(path)
    return found


def score_file(filepath: str) -> dict:
    """Score an instruction file and return detailed results."""
    if not os.path.isfile(filepath):
        return {"error": f"File not found: {filepath}", "score": 0}

    with open(filepath, encoding="utf-8", errors="replace") as f:
        content = f.read()

    lines = content.split("\n")
    line_count = len(lines)
    word_count = len(content.split())

    # ── Criterion 1: Specificity (0-20) ──
    # Concrete rules use: "do X", "don't Y", "always", "never", "must", "must not"
    specificity_patterns = [
        (r'\b(?:do|don\'?t|always|never|must|must\s+not|should\s+not|ensure)\b', 3),
        (r'```', 3),  # code examples
        (r'\b(?:e\.g\.|for example|specifically)\b', 2),
        (r'\b(?:error|warning|fail|break)\b', 2),
    ]
    specificity_score = 0
    for pattern, weight in specificity_patterns:
        matches = len(re.findall(pattern, content, re.IGNORECASE))
        specificity_score += min(matches * weight, 10)

    # Cap at 20
    specificity_score = min(specificity_score, 20)

    # ── Criterion 2: Project Conventions (0-15) ──
    convention_keywords = [
        r'\b(?:naming|convention|pattern|structure|organisation|organization|layout)\b',
        r'\b(?:file\s+name|directory|folder|path|module)\b',
        r'\b(?:import|require|dependency|package)\b',
    ]
    convention_score = 0
    for pattern in convention_keywords:
        if re.search(pattern, content, re.IGNORECASE):
            convention_score += 5
    convention_score = min(convention_score, 15)

    # ── Criterion 3: Test Guidance (0-15) ──
    test_keywords = [
        r'\b(?:test|tests|testing|coverage|spec)\b',
        r'\b(?:pytest|jest|mocha|vitest|unittest|rspec)\b',
        r'\b(?:run\s+tests?|test\s+command|how\s+to\s+test)\b',
    ]
    test_score = 0
    for pattern in test_keywords:
        if re.search(pattern, content, re.IGNORECASE):
            test_score += 5
    test_score = min(test_score, 15)

    # ── Criterion 4: Component Navigation (0-15) ──
    nav_keywords = [
        r'\b(?:src/|lib/|app/|components?/|pages/|routes?/)\b',
        r'\b(?:entry\s+point|main|index|app\b.*\bentry)\b',
        r'\b(?:architecture|dependency|depends\s+on|calls?|uses?)\b',
    ]
    nav_score = 0
    for pattern in nav_keywords:
        if re.search(pattern, content, re.IGNORECASE):
            nav_score += 5
    # Bonus for explicit file tree
    if re.search(r'├|└|│', content):
        nav_score += 5
    nav_score = min(nav_score, 15)

    # ── Criterion 5: Stack Details (0-10) ──
    stack_keywords = [
        r'\b(?:version|v\d+\.\d+|@\d+\.\d+)\b',
        r'\b(?:python|node|rust|go|typescript|javascript)\s+\d+\.\d+\b',
        r'\b(?:config|\.env|settings|setup)\b',
    ]
    stack_score = 0
    for pattern in stack_keywords:
        if re.search(pattern, content, re.IGNORECASE):
            stack_score += 3
    stack_score = min(stack_score, 10)

    # ── Criterion 6: Anti-patterns (0-10) ──
    antipattern_keywords = [
        r'\b(?:don\'?t|avoid|never|do\s+not|should\s+not|must\s+not|wrong)\b',
        r'\b(?:common\s+mistake|pitfall|gotcha|beware|warning)\b',
        r'\b(?:bad|incorrect|broken|anti.?pattern)\b',
    ]
    antipattern_score = 0
    for pattern in antipattern_keywords:
        matches = len(re.findall(pattern, content, re.IGNORECASE))
        antipattern_score += min(matches * 2, 6)
    antipattern_score = min(antipattern_score, 10)

    # ── Criterion 7: Scope Boundaries (0-10) ──
    scope_keywords = [
        r'\b(?:scope|boundary|limit|constraint|out\s+of\s+scope|in\s+scope)\b',
        r'\b(?:don\'?t\s+touch|leave\s+alone|hands?\s+off|do\s+not\s+modify)\b',
        r'\b(?:only|restrict|confine|within)\b',
    ]
    scope_score = 0
    for pattern in scope_keywords:
        if re.search(pattern, content, re.IGNORECASE):
            scope_score += 3
    scope_score = min(scope_score, 10)

    # ── Bonus: Structure (0-5) ──
    # Well-structured files use headings, bullet lists, and sections
    has_headings = bool(re.search(r'^#{1,3}\s', content, re.MULTILINE))
    has_lists = bool(re.search(r'^\s*[-*+]\s', content, re.MULTILINE))
    has_sections = len(re.findall(r'^#{1,3}\s', content, re.MULTILINE)) >= 3
    structure_bonus = (2 if has_headings else 0) + (1 if has_lists else 0) + (2 if has_sections else 0)

    total = specificity_score + convention_score + test_score + nav_score + stack_score + antipattern_score + scope_score + structure_bonus
    total = min(total, 100)

    # ── Recommendations ──
    recommendations = []

    if specificity_score < 10:
        recommendations.append("Add concrete rules: use 'do X', 'don't Y', 'always', 'never'. Include code examples (``` blocks).")
    if convention_score < 5:
        recommendations.append("Document naming conventions, file structure, and import patterns.")
    if test_score < 5:
        recommendations.append("Add test guidance: how to run tests, what framework, coverage expectations.")
    if nav_score < 5:
        recommendations.append("Map key directories (src/, lib/, routes/) and explain what lives where.")
    if stack_score < 3:
        recommendations.append("Specify language versions and key dependencies with versions.")
    if antipattern_score < 5:
        recommendations.append("List common mistakes to avoid — 'never do X because Y'.")
    if scope_score < 3:
        recommendations.append("Define what the agent should and shouldn't modify.")

    # Grade
    grade = "S" if total >= 90 else ("A" if total >= 75 else ("B" if total >= 60 else ("C" if total >= 40 else "D")))

    return {
        "file": filepath,
        "score": total,
        "grade": grade,
        "max_score": 100,
        "stats": {
            "lines": line_count,
            "words": word_count,
        },
        "breakdown": {
            "specificity": specificity_score,
            "conventions": convention_score,
            "test_guidance": test_score,
            "component_navigation": nav_score,
            "stack_details": stack_score,
            "antipatterns": antipattern_score,
            "scope_boundaries": scope_score,
            "structure_bonus": structure_bonus,
        },
        "recommendations": recommendations,
        "linted_at": datetime.now().isoformat(),
    }


def main():
    parser = argparse.ArgumentParser(description="AGENTS.md Linter — score instruction files for AI agent effectiveness")
    parser.add_argument("path", nargs="?", help="Path to instruction file")
    parser.add_argument("--dir", help="Directory to search for instruction files")
    args = parser.parse_args()

    if args.dir:
        files = find_instruction_files(args.dir)
        if not files:
            print(f"No instruction files found in {args.dir}")
            print(f"Looked for: CLAUDE.md, AGENTS.md, .cursorrules")
            sys.exit(1)
        print(f"Found {len(files)} instruction file(s) in {args.dir}\n")
        for f in files:
            result = score_file(f)
            print(f"  {os.path.basename(f)}: {result['score']}/100 ({result['grade']})")
        return
    elif args.path:
        result = score_file(args.path)
    else:
        parser.print_help()
        sys.exit(1)

    if "error" in result:
        print(f"Error: {result['error']}")
        sys.exit(1)

    print(f"\n{'─'*60}")
    print(f"  File: {result['file']}")
    print(f"  Score: {result['score']}/{result['max_score']} ({result['grade']})")
    print(f"  Stats: {result['stats']['lines']} lines, {result['stats']['words']} words")
    print(f"{'─'*60}")

    # Each criterion has its own max; normalise the bar to that max so a full
    # 10/10 reads as full, not half (the old bar assumed a fixed /20 scale).
    criterion_max = {
        "specificity": 20, "conventions": 15, "test_guidance": 15,
        "component_navigation": 15, "stack_details": 10, "antipatterns": 10,
        "scope_boundaries": 10, "structure_bonus": 5,
    }
    print(f"\n  Breakdown:")
    for criterion, score in result["breakdown"].items():
        cmax = criterion_max.get(criterion, 10) or 1
        filled = round(score / cmax * 10)
        bar = "█" * filled + "░" * (10 - filled)
        print(f"    {criterion.replace('_', ' ').title():25s} {score:3d}/{cmax:<3d} {bar}")

    if result["recommendations"]:
        print(f"\n  Recommendations:")
        for i, rec in enumerate(result["recommendations"], 1):
            print(f"    {i}. {rec}")

    print(f"\n  Grade scale: S (90+)  A (75-89)  B (60-74)  C (40-59)  D (<40)")
    print(f"  Method: regex keyword/structure heuristics, inspired by (not derived from)")
    print(f"  the Instructions-as-Code criteria. A high score is necessary, not sufficient.\n")


if __name__ == "__main__":
    main()
