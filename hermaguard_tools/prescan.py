"""Console-script entry point for the prescan tool."""

from ._loader import get_main


main = get_main('prescan')


if __name__ == "__main__":
    raise SystemExit(main())
