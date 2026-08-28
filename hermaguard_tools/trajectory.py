"""Console-script entry point for the trajectory tool."""

from ._loader import get_main


main = get_main('trajectory')


if __name__ == "__main__":
    raise SystemExit(main())
