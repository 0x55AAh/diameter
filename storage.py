#!/usr/bin/env python
import functools
from abc import ABC, abstractmethod
from typing import Callable

from cached_property import cached_property
from twisted.internet import defer

import config


def storage_request(func):
    @defer.inlineCallbacks
    @functools.wraps(func)
    def wrapper(storage, *args, **kwargs):
        res = yield func(storage, *args, **kwargs)
        if not callable(storage.formatter):
            raise ValueError("Formatter is improperly configured")
        return storage.formatter(res)
    return wrapper


class Storage(ABC):
    """
    Base storage class.
    Every request method must be marked with `storage_request` decorator.

    Example:
        @storage_request
        @defer.inlineCallbacks
        def user_data(self):
            ...
    """

    @property
    @abstractmethod
    def formatter(self) -> Callable:
        pass

    def __getattr__(self, item):
        raise RuntimeError(
            "Method is not implemented by storage: %s" % item)


class MockStorage(Storage):
    formatter: Callable = None


class BillingStorage(Storage):
    url: str = config.BILLING_API_URL
    formatter: Callable = None

    @cached_property
    def api(self):
        from billing import API
        return API(self.url)


if __name__ == "__name__":
    # noinspection PyUnresolvedReferences
    reactor.run()
