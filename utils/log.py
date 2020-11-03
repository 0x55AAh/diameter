import sys

from twisted.logger import (
    Logger, LogLevel, LogLevelFilterPredicate, FilteringLogObserver,
    textFileLogObserver, globalLogPublisher
)

__all__ = ["logger"]

predicate = LogLevelFilterPredicate(defaultLogLevel=LogLevel.debug)
observer = FilteringLogObserver(textFileLogObserver(sys.stdout), [predicate])
observer._encoding = "utf-8"
globalLogPublisher.addObserver(observer)

logger = Logger()
