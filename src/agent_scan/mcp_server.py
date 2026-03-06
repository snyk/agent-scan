import asyncio
import json
import logging
import os
import random
import sys
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

import filelock
import psutil
import rich
from mcp.server.fastmcp import FastMCP
from rich.logging import RichHandler

from agent_scan.cli import run_scan
from agent_scan.mcp_client import scan_mcp_config_file
from agent_scan.models import StdioServer

logger = logging.getLogger(__name__)


# start a thread that runs the do_agent_scan function
def thread_fn(path, args, stop_event):
    logger.info("Launching scanning thread")
    t = threading.current_thread()
    jitter = random.randint(0, 10)
    sleep_time = 10 + jitter  # initially sleep for 10 + jitter seconds to avoid race conditions on startup
    while getattr(t, "do_run", True):
        # Use event.wait() for interruptible sleep
        if stop_event.wait(timeout=sleep_time):
            # Event was set, we should stop
            logger.info("Recieved stop event; stopping")
            break
        logger.info("Waking up to perform scan")
        sleep_time = asyncio.run(perform_and_schedule_scan(path, args))
        if sleep_time is None:
            sleep_time = 10  # seconds


class Scanner:
    def __init__(self, args):
        self.thread = None
        self.args = args
        self.storage_path = os.path.expanduser(args.storage_file)
        os.makedirs(self.storage_path, exist_ok=True)
        self.scan_path = os.path.join(self.storage_path, "background_scan.json")
        self.stop_event = threading.Event()
        logger.info("Scanner initialized")

    def start(self):
        logger.info("Starting scanner thread")
        self.thread = threading.Thread(target=thread_fn, args=(self.scan_path, self.args, self.stop_event))
        self.thread.start()

    def stop(self):
        logger.info("Stopping scanner thread")
        self.thread.do_run = False
        self.stop_event.set()  # Signal the thread to wake up and stop
        self.thread.join()


def setup_mcp_server_logging(log_path):
    # Create a root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # Clear any existing handlers
    root_logger.handlers.clear()

    # Create formatter for file handler (plain text)
    file_formatter = logging.Formatter(fmt="%(message)s", datefmt="[%X]")

    # Create file handler
    file_handler = logging.FileHandler(log_path, mode="a")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)

    # Create stderr handler with Rich formatting
    stderr_console = rich.console.Console(stderr=True)
    stderr_handler = RichHandler(markup=True, rich_tracebacks=True, console=stderr_console)
    stderr_handler.setLevel(logging.DEBUG)
    # Rich handler uses its own formatting, so no need to set a formatter

    # Add handlers to root logger
    root_logger.addHandler(file_handler)
    root_logger.addHandler(stderr_handler)


async def perform_and_schedule_scan(path, args):
    # aquire lock on the path in a cross-OS way
    lock_path = path + ".lock"

    # get the scheduler id
    scheduler_id = os.getpid()

    # time delta betwen two scans
    scan_interval = args.scan_interval

    # time to sleep after the scan is done
    sleep_time = timedelta(seconds=scan_interval)

    logger.info(f"Determining scan status using lock: {lock_path}")
    lock = filelock.FileLock(lock_path, timeout=scan_interval)
    with lock:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    data = json.load(f)
                    # sid = data.get("scheduler_id", None)
                    sdate = datetime.fromisoformat(data.get("scheduled_scan", None))
            except Exception as e:
                logger.error(f"Error loading scan data: {e}")
                data = {}
                # sid = None
                sdate = None
        else:
            logger.info("No scan data file found")
            data = {}
            # sid = None
            sdate = None

        now = datetime.now()
        if (sdate is not None and sdate < now) or (sdate is None):
            if sdate is not None:
                logger.info(f"Scan is scheduled for {sdate}; running scan")
            else:
                logger.info("No scan is scheduled; running scan")
            result = await run_scan(args, mode="scan")

            # Convert result to JSON format for return
            result_dict = {r.path: r.model_dump(mode="json") for r in result}
            now = datetime.now()
            data["last_scan"] = now.isoformat()
            data["results"] = result_dict

            # schedule the next scan
            data["scheduler_id"] = scheduler_id
            then = now + timedelta(seconds=scan_interval)
            data["scheduled_scan"] = then.isoformat()
            logger.info(f"Scheduling next scan for {then}")
        elif sdate is not None and sdate > now:
            logger.info(f"Scan is scheduled for {sdate}; sleeping until then")
            # scan is in the future; do nothing
            # sleep until next scan
            sleep_time = sdate - now

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    # add 5 milliseconds to the sleep time
    sleep_time += timedelta(milliseconds=5)
    logger.info(f"Sleeping for {sleep_time.total_seconds()} seconds")
    return sleep_time.total_seconds()


def create_lifespan_context(args):
    @asynccontextmanager
    async def lifespan(mcp: FastMCP) -> AsyncIterator[object]:
        scanner = Scanner(args)
        if args.background:
            try:
                scanner.start()
                yield {"scanner": scanner}
            finally:
                scanner.stop()
        else:
            yield {"scanner": scanner}

    return lifespan


def install_mcp_server(args):
    if args.file is None:
        rich.print("File to install the MCP server in is required")
        return 1
    if not os.path.exists(args.file):
        rich.print(f"File {args.file} does not exist")
        return 1

    # get args
    lock_path = args.file + ".lock"
    lock = filelock.FileLock(lock_path, timeout=1)
    path = os.path.expanduser(args.file)
    with lock:
        config = asyncio.run(scan_mcp_config_file(path))
        parent = psutil.Process().parent()
        cmd = parent.cmdline()
        cmd = [c.replace("install-mcp-server", "mcp-server") for c in cmd]

        # remove the file argument
        idx = cmd.index(args.file)
        if idx >= 0:
            cmd = cmd[:idx] + cmd[idx + 1 :]

        if "agent-scan" in config.mcpServers:
            rich.print(f"MCP server already installed in {path}; Updating configuration")
        config.mcpServers["agent-scan"] = StdioServer(name="agent-scan", command=cmd[0], args=cmd[1:])
        rich.print(f"Installed MCP server in {path}")
        with open(os.path.expanduser(path), "w") as f:
            f.write(config.model_dump_json(indent=4) + "\n")
            # flush the file to disk
            f.flush()
            os.fsync(f.fileno())
    return 0


def _get_mcp_server_log_path(storage_path: str, pid: int, client_name: str | None = None) -> str:
    date = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
    log_dir = os.path.join(storage_path, "mcp_server")
    os.makedirs(log_dir, exist_ok=True)
    file = os.path.join(log_dir, f"{date}_{pid}_{client_name}.log")
    if not os.path.exists(file):
        with open(file, "w") as f:
            f.write("")
    return file


def mcp_server(args):
    lifespan = create_lifespan_context(args)
    storage_path = os.path.expanduser(args.storage_file)
    os.makedirs(storage_path, exist_ok=True)
    setup_mcp_server_logging(_get_mcp_server_log_path(storage_path, os.getpid(), args.client_name))

    logger.info(f"Starting MCP server with args: {args}")
    logger.info(f"Storage path: {args.storage_file}")

    instructions = """
        This is a MCP server that scans this agent (and the MCP servers it uses) for MCP--related security vunerabilities.
        """
    if args.background:
        instructions += "\nScans are performed periodically in the background."
        if args.tool:
            instructions += "\nCall the get_scan_results tool to obtain the results."
    else:
        if args.tool:
            instructions += "\nScans can be performed by calling the scan tool."
        else:
            logger.error("either background or tool must be true")
            sys.exit(1)

    logger.info(f"Instructions: {instructions}")

    mcp = FastMCP("MCP Scan", instructions=instructions, lifespan=lifespan)

    if args.background and args.tool:
        logger.info("Adding get_scan_results tool")

        @mcp.tool()
        async def get_scan_results() -> str:
            """Returns the results of the last scan"""
            path = os.path.join(storage_path, "background_scan.json")
            lock_path = path + ".lock"
            with filelock.FileLock(lock_path, timeout=1):
                with open(path) as f:
                    data = json.load(f)
                    results = data.get("results", {})
                    return json.dumps(results, indent=2)
    elif args.tool:
        logger.info("Adding scan tool")

        @mcp.tool()
        async def scan() -> str:
            """Performs a the current MCP setup (this client + tools it uses)"""

            # Run the actual scan
            result = await run_scan(args, mode="scan")

            # Convert result to JSON format for return
            result_dict = {r.path: r.model_dump(mode="json") for r in result}
            return json.dumps(result_dict, indent=2)

    logger.info("Starting MCP server")
    return mcp.run()
