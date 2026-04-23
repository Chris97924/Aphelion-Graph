"""Module entrypoint for `python -m dpkg`."""

from dpkg.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
