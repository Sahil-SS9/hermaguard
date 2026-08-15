"""Console-script entry point for the verify tool."""

from ._loader import get_main


main = get_main('verify')


if __name__ == "__main__":
    raise SystemExit(main())
