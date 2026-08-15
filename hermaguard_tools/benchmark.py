"""Console-script entry point for the benchmark tool."""

from ._loader import get_main


main = get_main('benchmark')


if __name__ == "__main__":
    raise SystemExit(main())
