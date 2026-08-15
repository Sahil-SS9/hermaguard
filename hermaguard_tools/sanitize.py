"""Console-script entry point for the sanitize tool."""

from ._loader import get_main


main = get_main('sanitize')


if __name__ == "__main__":
    raise SystemExit(main())
