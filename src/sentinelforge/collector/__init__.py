"""Log collectors."""

from .base import Collector, CollectorError, local_hostname
from .file import (
    DEFAULT_LOG_PATHS,
    FileCollector,
    FilesCollector,
    detect_log_files,
    parse_syslog_line,
    unreadable_log_files,
)
from .journal import JournalCollector, journal_available

__all__ = [
    "Collector",
    "CollectorError",
    "DEFAULT_LOG_PATHS",
    "FileCollector",
    "FilesCollector",
    "JournalCollector",
    "detect_log_files",
    "journal_available",
    "local_hostname",
    "parse_syslog_line",
    "unreadable_log_files",
]
