"""Console-script entry point for the locate tool."""

from ._loader import get_main


main = get_main('locate')


if __name__ == "__main__":
    raise SystemExit(main())
