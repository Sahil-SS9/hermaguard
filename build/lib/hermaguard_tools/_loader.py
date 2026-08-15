"""Loader: resolve a hermaguard tool script and return its module.

Resolution order:
  1. Source checkout: walk up from this package to the repo root (tools/).
  2. pip install: sys.prefix/share/hermaguard/tools (setuptools data-files).
"""

import importlib.util
import inspect
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent

# Console-script name -> (tool dir name, preferred file stem)
TOOL_LAYOUT = {
    "coverage": ("hermaguard-coverage", "hermaguard-coverage"),
    "locate": ("hermaguard-locate", "hermaguard-locate"),
    "role_patterns": ("hermaguard-role-patterns", "hermaguard-role-patterns"),
    "sanitize": ("hermaguard-sanitize", "hermaguard-sanitize"),
    "verify": ("hermaguard-verify", "hermaguard-verify"),
    "grader": ("hermaguard-grader", "hermaguard_grader"),
    "prescan": ("hermaguard-prescan", "hermaguard-prescan"),
    "compile_rules": ("hermaguard-compile-rules", "hermaguard-compile-rules"),
    "benchmark": ("hermaguard-benchmark", "benchmark"),
}


def _find_tools_root() -> Path:
    """Locate the tools/ directory (source checkout or pip data-files)."""
    # Source checkout: hermaguard_tools/ sits at repo root.
    for parent in _HERE.parents:
        cand = parent / "tools"
        if (cand / "hermaguard-coverage" / "hermaguard-coverage.py").is_file():
            return cand
    # pip install: data-files land under sys.prefix/share/hermaguard/tools.
    # NOTE: setuptools data-files FLATTEN the tree, so the tool scripts sit
    # directly in that dir (no per-tool subdirectories).
    cand = Path(sys.prefix) / "share" / "hermaguard" / "tools"
    if cand.is_dir() and any(cand.glob("*.py")):
        return cand
    raise ImportError(
        "hermaguard tools/ not found — run from the repo checkout, or install "
        "with `pip install .` (data-files include the tools)."
    )


def load_tool(name: str):
    """Import and return the module for the named tool (cached)."""
    mod_name = f"hermaguard_tools._tool_{name}"
    if mod_name in sys.modules:
        return sys.modules[mod_name]
    dir_name, stem = TOOL_LAYOUT[name]
    root = _find_tools_root()
    # Source checkout layout: tools/<dir>/<stem>.py
    script = root / dir_name / f"{stem}.py"
    if not script.is_file():
        # Pip data-files layout: tools/<stem>.py (flattened)
        script = root / f"{stem}.py"
    if not script.is_file():
        raise ImportError(f"hermaguard tool not found: {stem}")
    spec = importlib.util.spec_from_file_location(mod_name, script)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {script}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def get_main(name: str):
    """Return a callable main() for the named tool.

    Some tools define main(argv) (grader) and others main() — wrap argv-taking
    mains so console scripts can call them uniformly with sys.argv[1:].
    """
    mod = load_tool(name)
    if not hasattr(mod, "main"):
        raise ImportError(f"{name} has no main()")
    fn = mod.main
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        sig = None
    if sig is not None and any(
        p.kind == inspect.Parameter.POSITIONAL_OR_KEYWORD for p in sig.parameters.values()
    ):
        def _wrapped_argv():
            return fn(sys.argv[1:])
        return _wrapped_argv
    return fn
