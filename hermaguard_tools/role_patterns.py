"""Console-script entry point for the role_patterns tool."""

from ._loader import get_main


main = get_main('role_patterns')


if __name__ == "__main__":
    raise SystemExit(main())
