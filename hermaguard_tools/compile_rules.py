"""Console-script entry point for the compile_rules tool."""

from ._loader import get_main


main = get_main('compile_rules')


if __name__ == "__main__":
    raise SystemExit(main())
