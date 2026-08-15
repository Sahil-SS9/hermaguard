"""Console-script entry point for the grader tool."""

from ._loader import get_main


main = get_main('grader')


if __name__ == "__main__":
    raise SystemExit(main())
