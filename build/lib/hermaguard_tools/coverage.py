"""Console-script entry point for the coverage tool."""

from ._loader import get_main


main = get_main('coverage')


if __name__ == "__main__":
    raise SystemExit(main())
