import asyncio
import sys

from agent_scan.cli import main
from agent_scan.verify_api import SnykTokenError


def run():
    try:
        asyncio.run(main())
    except SnykTokenError:
        sys.exit(1)


if __name__ == "__main__":
    run()
