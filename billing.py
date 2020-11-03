#!/usr/bin/env python
import json
import warnings
from typing import Optional, Any

from twisted.internet import reactor, defer
from twisted.web.client import Agent, readBody
from twisted.web.http_headers import Headers


class API:
    """Billing API."""

    agent = Agent(reactor)
    base_url: str = None

    def __init__(self, url: Optional[str] = None):
        if self.base_url is None:
            self.base_url = url

    def url(self, path: str) -> bytes:
        base_url = self.base_url.rstrip("/")
        path = path.lstrip("/")
        url = base_url + "/" + path
        return url.encode()

    @defer.inlineCallbacks
    def request(self, path: str, method: str = "GET",
                headers: Optional[dict] = None) -> Any:
        default_headers = {
            'Content-Type': ['application/json'],
        }
        if headers:
            default_headers.update(headers)
        headers = Headers(default_headers)
        url = self.url(path)
        if isinstance(method, str):
            method = method.encode()
        res = yield self.agent.request(method, url, headers, None)
        warnings.simplefilter('ignore', category=DeprecationWarning)
        data = yield readBody(res)
        return json.loads(data)

    @defer.inlineCallbacks
    def get(self, url: str, headers: Optional[dict] = None) -> Any:
        res = yield self.request(url, "GET", headers)
        return res


if __name__ == "__main__":
    api = API(url="http://jsonplaceholder.typicode.com/posts")

    def do_requests():
        res = api.get("/storage")

        def cb_response(response):
            print(response)

        res.addCallback(cb_response)

    # noinspection PyUnresolvedReferences
    reactor.callLater(1, do_requests)
    # noinspection PyUnresolvedReferences
    reactor.run()
