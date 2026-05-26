#!/usr/bin/env python3
"""
DSPloit PC Logger — Panic-Safe Real-Time Log Capture

Captures ALL device logs via USB syslog relay in real-time.
Logs are saved to PC immediately (flush every line).
If device panics, you know EXACTLY which step caused it.

Usage:
    python pc_logger.py                  # Auto-detect device, start logging
    python pc_logger.py --experiment     # Tag session as experiment
    python pc_logger.py --filter dsploit # Only show DSPloit-related logs
    python pc_logger.py --list           # List saved log sessions

Requirements:
    pip install pymobiledevice3 rich

How it works:
    1. Connects to iPhone via USB (pymobiledevice3)
    2. Opens syslog relay service
    3. Streams ALL device logs to PC terminal + file
    4. Every line is flushed immediately (panic-safe)
    5. If device disconnects (panic/reboot), logs are preserved
    6. Shows "LAST STEP BEFORE PANIC" analysis

DSPloit Integration:
    - DSPloit app logs with prefix "(jb)", "(pe)", "(exp_)", "(root)"
    - This script captures those and highlights them
    - When device panics mid-experiment, check the log file
    - Last DSPloit log entry = the step that caused panic
"""

import sys
import os
import time
import signal
import argparse
from datetime import datetime
from pathlib import Path

try:
    from pymobiledevice3.remote.common import TunnelProtocol
    from pymobiledevice3.usbmux import list_devices as _list_devices_async
    from pymobiledevice3.lockdown import create_using_usbmux as _create_using_usbmux
    from pymobiledevice3.services.os_trace import OsTraceService
    import asyncio
    PMD3_AVAILABLE = True
except ImportError:
    PMD3_AVAILABLE = False

if not PMD3_AVAILABLE:
    print("ERROR: pymobiledevice3 not installed or incompatible version")
    print("Run: pip install pymobiledevice3")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# ============================================================
# Configuration
# ============================================================

LOG_DIR = Path(__file__).parent.parent / "logs"
DSPLOIT_PREFIXES = [
    "(jb)", "(pe)", "(ds)", "(exp_", "(root)", "(amfi)",
    "(tc)", "(sbx)", "(vfs)", "(rc)", "(krw)", "(offset)",
    "(exp_csflags)", "(exp_tc)", "(exp_amfid)",
    "[DSPloit]", "(appreg)", "(kcmgr)", "(kcache)",
    "(fetchkcache)", "(ka)", "(getbmhash)", "(rcallAddr)",
]
PANIC_KEYWORDS = ["panic", "kernel panic", "watchdog timeout", "KTRR", "PPL"]


# ============================================================
# Logger Class
# ============================================================

class DSPloitLogger:
    def __init__(self, experiment_mode=False, filter_prefix=None, verbose=True):
        self.experiment_mode = experiment_mode
        self.filter_prefix = filter_prefix
        self.verbose = verbose
        self.console = Console() if RICH_AVAILABLE else None
        self.session_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.log_file = None
        self.line_count = 0
        self.dsploit_lines = []
        self.last_dsploit_line = ""
        self.device_connected = False
        self.running = True

        # Create log directory
        LOG_DIR.mkdir(parents=True, exist_ok=True)

        # Setup log file
        tag = "experiment" if experiment_mode else "session"
        filename = f"{self.session_id}_{tag}.log"
        self.log_path = LOG_DIR / filename
        self.log_file = open(self.log_path, "w", encoding="utf-8", buffering=1)  # line-buffered

        self._print_header()

    def _print_header(self):
        header = f"""
╔══════════════════════════════════════════════════════════════╗
║  DSPloit PC Logger — Panic-Safe Real-Time Capture            ║
║  Session: {self.session_id}                        ║
║  Log file: {self.log_path.name:<47}║
║  Mode: {"EXPERIMENT" if self.experiment_mode else "MONITOR":<52}║
╚══════════════════════════════════════════════════════════════╝
"""
        print(header)
        self.log_file.write(header)
        self.log_file.flush()

    def _colorize(self, line):
        """Apply color based on content."""
        if not RICH_AVAILABLE:
            return line

        text = Text(line)

        # DSPloit exploit logs — green
        if any(p in line for p in DSPLOIT_PREFIXES):
            text.stylize("bold green")
        # Errors — red
        elif "error" in line.lower() or "fail" in line.lower():
            text.stylize("red")
        # Panic keywords — bold red background
        elif any(k in line.lower() for k in PANIC_KEYWORDS):
            text.stylize("bold white on red")
        # Warnings — yellow
        elif "warn" in line.lower():
            text.stylize("yellow")
        # Success markers
        elif "✅" in line or "success" in line.lower():
            text.stylize("bold green")
        # Step markers
        elif "step" in line.lower() or "STEP" in line:
            text.stylize("bold cyan")

        return text

    def _is_dsploit_log(self, line):
        """Check if this log line is from DSPloit app."""
        return any(p in line for p in DSPLOIT_PREFIXES) or "DSPloit" in line or "lara" in line

    def log_line(self, line):
        """Process and save one log line. FLUSH immediately."""
        self.line_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        formatted = f"[{timestamp}] {line}"

        # Always write to file (panic-safe — flushed immediately)
        self.log_file.write(formatted + "\n")
        self.log_file.flush()
        os.fsync(self.log_file.fileno())  # Force to disk

        # Track DSPloit-specific lines
        if self._is_dsploit_log(line):
            self.dsploit_lines.append(formatted)
            self.last_dsploit_line = formatted
            # Keep last 100 DSPloit lines in memory
            if len(self.dsploit_lines) > 100:
                self.dsploit_lines.pop(0)

        # Display to terminal
        if self.filter_prefix:
            if self.filter_prefix.lower() in line.lower():
                self._display(formatted)
        elif self.verbose or self._is_dsploit_log(line):
            self._display(formatted)

    def _display(self, line):
        """Print to terminal with optional color."""
        if self.console and RICH_AVAILABLE:
            self.console.print(self._colorize(line))
        else:
            print(line)

    def on_disconnect(self):
        """Called when device disconnects (possible panic)."""
        self.device_connected = False

        report = f"""
╔══════════════════════════════════════════════════════════════╗
║  ⚠️  DEVICE DISCONNECTED                                     ║
║  Possible kernel panic or reboot                             ║
╠══════════════════════════════════════════════════════════════╣
║  PANIC ANALYSIS:                                             ║
║                                                              ║
║  Total lines captured: {self.line_count:<37}║
║  DSPloit lines captured: {len(self.dsploit_lines):<35}║
║                                                              ║
║  LAST DSPloit LOG ENTRY (likely panic trigger):              ║
"""
        if self.last_dsploit_line:
            # Truncate if too long
            last = self.last_dsploit_line[:58]
            report += f"║  {last:<60}║\n"
        else:
            report += "║  (no DSPloit logs captured)                                  ║\n"

        report += "║                                                              ║\n"
        report += "║  Last 5 DSPloit entries:                                     ║\n"

        for entry in self.dsploit_lines[-5:]:
            truncated = entry[:58]
            report += f"║  {truncated:<60}║\n"

        report += "║                                                              ║\n"
        report += f"║  Full log saved: {self.log_path.name:<43}║\n"
        report += "╚══════════════════════════════════════════════════════════════╝\n"

        print(report)
        self.log_file.write(report)
        self.log_file.flush()

    def close(self):
        """Close log file gracefully."""
        if self.log_file:
            summary = f"\n--- Session ended: {datetime.now().isoformat()} ---\n"
            summary += f"--- Total lines: {self.line_count} ---\n"
            summary += f"--- DSPloit lines: {len(self.dsploit_lines)} ---\n"
            self.log_file.write(summary)
            self.log_file.close()
            print(f"\nLog saved: {self.log_path}")


# ============================================================
# Device Connection
# ============================================================

def connect_device():
    """Find and connect to iOS device via USB. Returns (lockdown, udid)."""
    print("Searching for iOS device via USB...")
    # We just return the UDID here — actual connection happens in stream_syslog
    try:
        async def _find():
            devices = await _list_devices_async()
            return devices
        devices = asyncio.run(_find())
    except Exception as e:
        print(f"ERROR: {e}")
        return None

    if not devices:
        print("ERROR: No iOS device found. Connect via USB and trust this computer.")
        return None

    device = devices[0]
    udid = device.serial if hasattr(device, 'serial') else str(device)
    print(f"Found device: {udid}")
    return udid


def stream_syslog(udid, logger):
    """Stream device syslog to logger. Handles full async lifecycle."""
    print("\nStarting syslog relay... (Ctrl+C to stop)\n")
    print("=" * 60)
    logger.device_connected = True

    async def _full_stream():
        # Connect + stream in same event loop
        lockdown = await _create_using_usbmux(serial=udid)
        device_name = lockdown.display_name
        ios_version = lockdown.product_version
        model = lockdown.product_type
        print(f"  Device: {device_name} ({model}) — iOS {ios_version}")

        service = OsTraceService(lockdown=lockdown)
        async for entry in service.syslog():
            if not logger.running:
                break
            if entry:
                if hasattr(entry, 'message'):
                    msg = entry.message or ''
                    pid = getattr(entry, 'pid', '')
                    line = f"[{pid}] {msg}"
                else:
                    line = str(entry)
                if line.strip():
                    logger.log_line(line.strip())

    try:
        asyncio.run(_full_stream())
    except KeyboardInterrupt:
        pass
    except (ConnectionError, OSError, BrokenPipeError):
        if logger.device_connected:
            logger.on_disconnect()
    except Exception as e:
        err_str = str(e).lower()
        if "closed" in err_str or "terminated" in err_str or "eof" in err_str:
            if logger.device_connected:
                logger.on_disconnect()
        else:
            print(f"Syslog error: {e}")
            if logger.device_connected:
                logger.on_disconnect()


# ============================================================
# Log Viewer (for past sessions)
# ============================================================

def list_logs():
    """List all saved log sessions."""
    if not LOG_DIR.exists():
        print("No logs directory found.")
        return

    logs = sorted(LOG_DIR.glob("*.log"), reverse=True)
    if not logs:
        print("No log files found.")
        return

    print(f"\nSaved log sessions ({LOG_DIR}):\n")
    print(f"{'#':<4} {'Date/Time':<22} {'Type':<12} {'Size':<10} {'File'}")
    print("-" * 80)

    for i, log in enumerate(logs[:20], 1):
        size = log.stat().st_size
        size_str = f"{size / 1024:.1f} KB" if size > 1024 else f"{size} B"
        tag = "EXPERIMENT" if "experiment" in log.name else "SESSION"
        date_part = log.stem[:19].replace("_", " ", 1).replace("-", "/", 2)
        print(f"{i:<4} {date_part:<22} {tag:<12} {size_str:<10} {log.name}")


def show_panic_summary(log_path):
    """Show panic analysis for a specific log file."""
    path = Path(log_path)
    if not path.exists():
        print(f"File not found: {log_path}")
        return

    dsploit_lines = []
    total_lines = 0

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            total_lines += 1
            if any(p in line for p in DSPLOIT_PREFIXES):
                dsploit_lines.append(line.strip())

    print(f"\nPanic Analysis: {path.name}")
    print("=" * 60)
    print(f"Total lines: {total_lines}")
    print(f"DSPloit lines: {len(dsploit_lines)}")
    print(f"\nLast 10 DSPloit entries before disconnect:")
    print("-" * 60)
    for line in dsploit_lines[-10:]:
        print(f"  {line}")
    print("-" * 60)
    if dsploit_lines:
        print(f"\n⚠️  LIKELY PANIC TRIGGER: {dsploit_lines[-1]}")


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="DSPloit PC Logger — Panic-Safe Real-Time Log Capture"
    )
    parser.add_argument("--experiment", "-e", action="store_true",
                        help="Tag this session as an experiment run")
    parser.add_argument("--filter", "-f", type=str, default=None,
                        help="Only show lines containing this string")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Only show DSPloit-related logs (hide system noise)")
    parser.add_argument("--list", "-l", action="store_true",
                        help="List saved log sessions")
    parser.add_argument("--analyze", "-a", type=str, default=None,
                        help="Analyze a specific log file for panic info")

    args = parser.parse_args()

    # List mode
    if args.list:
        list_logs()
        return

    # Analyze mode
    if args.analyze:
        show_panic_summary(args.analyze)
        return

    # Live capture mode
    logger = DSPloitLogger(
        experiment_mode=args.experiment,
        filter_prefix=args.filter,
        verbose=not args.quiet,
    )

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        logger.running = False
        logger.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Connect and stream
    udid = connect_device()
    if not udid:
        logger.close()
        sys.exit(1)

    # Retry loop (reconnect after panic/reboot)
    while logger.running:
        stream_syslog(udid, logger)

        if not logger.running:
            break

        # Device disconnected — wait for reconnect
        print("\nWaiting for device to reconnect (reboot)...")
        print("Press Ctrl+C to stop.\n")

        reconnected = False
        for attempt in range(60):  # Wait up to 60 seconds
            time.sleep(1)
            try:
                async def _reconnect():
                    devices = await _list_devices_async()
                    if devices:
                        device = devices[0]
                        return device.serial if hasattr(device, 'serial') else str(device)
                    return None

                new_udid = asyncio.run(_reconnect())
                if new_udid:
                    udid = new_udid
                    print(f"Device reconnected! Resuming log capture...")
                    logger.device_connected = True
                    reconnected = True
                    break
            except Exception:
                pass

        if not reconnected:
            print("Device did not reconnect within 60s. Exiting.")
            break

    logger.close()


if __name__ == "__main__":
    main()
