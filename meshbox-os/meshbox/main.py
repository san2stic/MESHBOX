"""
MeshBox — Main entry point for the SANP mesh network daemon.

Usage::

    python -m meshbox.main
    # or
    meshbox start
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from pathlib import Path

from meshbox.node.meshbox_daemon import MeshBoxDaemon


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


async def _run_daemon(
    data_dir: str = "~/.meshbox",
    sanp_port: int = 7777,
    api_port: int = 8080,
    passphrase: str = "",
    seeds: list[str] | None = None,
) -> None:
    daemon = MeshBoxDaemon(
        data_dir=data_dir,
        sanp_port=sanp_port,
        api_port=api_port,
        passphrase=passphrase,
        bootstrap_seeds=seeds,
    )

    loop = asyncio.get_event_loop()

    def _signal_handler():
        asyncio.ensure_future(daemon.stop())

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _signal_handler)

    try:
        await daemon.start()
        # Run forever until stop() is called
        while daemon._running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        await daemon.stop()


def main() -> None:
    _setup_logging(verbose="--verbose" in sys.argv or "-v" in sys.argv)
    asyncio.run(
        _run_daemon(
            data_dir="~/.meshbox",
            sanp_port=7777,
            api_port=8080,
        )
    )


if __name__ == "__main__":
    main()
