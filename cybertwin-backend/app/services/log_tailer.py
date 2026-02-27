"""
Log Tailer Service – Track B (Production)
Watches a real Snort/OSSEC log file and tails new lines as they appear.

Activated when LOG_FILE_PATH is set in .env.
On Windows dev, point this at a Docker volume-mounted alert file.
"""

import asyncio
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


async def tail_log_file(file_path: str, callback, poll_interval: float = 0.5):
    """
    Async file tailer. Seeks to end of file, then yields new lines as they appear.

    Args:
        file_path: Absolute path to the Snort/OSSEC alert log file.
        callback: async callable(raw_log: str, source_hint: str)
        poll_interval: How often to poll the file for new lines (seconds).
    """
    path = Path(file_path)
    logger.info(f"[Tailer] Tailing log file: {path}")

    # Determine source hint from filename
    source_hint = "snort" if "snort" in path.name.lower() else "ossec"

    # Wait for the file to exist
    while not path.exists():
        logger.warning(f"[Tailer] File not found: {path} – retrying in 5s")
        await asyncio.sleep(5)

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        # Seek to end so we only get new lines
        f.seek(0, 2)

        buffer = []
        while True:
            try:
                line = f.readline()
                if line:
                    stripped = line.strip()
                    if stripped:
                        buffer.append(stripped)
                    elif buffer:
                        # Empty line signals end of a multi-line alert (OSSEC style)
                        full_entry = "\n".join(buffer)
                        await callback(full_entry, source_hint)
                        buffer = []
                else:
                    # No new data – flush any pending single-line (Snort style)
                    if buffer:
                        full_entry = "\n".join(buffer)
                        await callback(full_entry, source_hint)
                        buffer = []
                    await asyncio.sleep(poll_interval)

                    # Handle log rotation: re-open if file shrank
                    current_pos = f.tell()
                    new_size = path.stat().st_size
                    if new_size < current_pos:
                        logger.info("[Tailer] Log rotation detected. Re-opening file.")
                        f.seek(0)

            except asyncio.CancelledError:
                logger.info("[Tailer] Tailer task cancelled")
                break
            except Exception as e:
                logger.error(f"[Tailer] Error reading file: {e}")
                await asyncio.sleep(2)
