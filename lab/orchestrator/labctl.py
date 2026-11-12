"""Entry point: python labctl.py <command> (see python labctl.py --help). Needs Python 3.11+, no packages."""
import sys

if sys.version_info < (3, 11):
    sys.exit("labctl needs Python 3.11 or newer (tomllib)")

from mglab.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
