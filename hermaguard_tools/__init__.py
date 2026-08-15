"""hermaguard_tools — package shim that exposes the flat hermaguard tools as
importable modules with console-script entry points.

The tools live as standalone scripts under tools/ (each is self-contained,
stdlib-only, runnable without install). This package locates them at runtime
— from the source checkout, or from the package-data copy when installed via
pip — and exposes each tool's `main` function as a clean console script.
"""
