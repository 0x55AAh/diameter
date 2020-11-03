#!/usr/bin/env python
import time
from dataclasses import dataclass
from typing import Optional, Dict, Callable

from twisted.internet import reactor
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.internet.protocol import Protocol, Factory

import config
from diameter import (
    Message, Dictionary, load_wireshark_dict, parse_xml
)
from storage import Storage, BillingStorage, MockStorage
from utils.log import logger

__all__ = [
    "BaseDiameterProtocol",
    "DiameterProtocol",
    "BillingDiameterProtocol",
    "DiameterFactory",
]


def _load_dictionary() -> Dictionary:
    xml = load_wireshark_dict("diameter", "dictionary.xml")
    return Dictionary(parse_xml(xml))


@dataclass
class PendingRequest:
    message: Message
    deferred: Deferred


class BaseDiameterProtocol(Protocol):
    """Base diameter protocol implementation."""

    _dictionary: Dictionary = _load_dictionary()
    request_timeout: int = 300  # 5 min
    storage: Storage = None

    # noinspection PyAttributeOutsideInit
    def connectionMade(self):
        self._buff: bytes = b""
        self._pending_requests: Dict[int, PendingRequest] = {}
        self._hop_by_hop: int = int(time.time())  # Not by RFC, but close enough

    # noinspection PyBroadException
    def dataReceived(self, data: bytes):
        self._buff += data
        try:
            while True:
                message = Message(self._dictionary)
                try:
                    message.decode(self._buff)
                except Exception:
                    # Message has been collected in the buffer, but not entirely.
                    # So, end this event handler, and wait for another
                    # data event, with the rest of the message.
                    return
                # noinspection PyAttributeOutsideInit
                self._buff = self._buff[message.hdr.len:]
                self.on_message(message)
        except Exception:
            self.on_error()

    def _storage_method(self, cmd: str) -> Callable:
        """
        Translate command name into appropriate storage method.

        Example:
            def protocol_method(self, cmd):
                storage_method = self._storage_method(cmd)
                d:Deferred = storage_method()
                ...
        """
        cmd = self._command_name_normalized(cmd)
        return getattr(self.storage, cmd)

    @classmethod
    def _command_name_normalized(cls, command: str) -> str:
        """
        Converts command name to valid python name.

        Example:
            Capabilities-Exchange -> capabilities_exchange
        """
        return command.lower().replace("-", "_")

    @classmethod
    def get_session_id(cls, message: Message) -> str:
        """Get session ID from message."""
        avp = next((x for x in message.avps if x[0] == "Session-Id"), None)
        if avp is not None:
            return avp[2]

    def get_command_name(self, message: Message) -> str:
        """Get command name from message."""
        command = self._dictionary.command_name(message.hdr.flags,
                                                message.hdr.code,
                                                message.hdr.appid)
        command = command.split()
        return command[0]

    def on_message(self, message: Message) -> None:
        """Root message handler."""
        if message.hdr.is_proxiable:
            self.do_forward(message)
        elif message.hdr.is_request:
            command = self.get_command_name(message)
            logger.debug("Got request {command}: {message}",
                         command=command, message=message)
            handler_name = "on_" + self._command_name_normalized(command)
            message_handler = getattr(self, handler_name, None)
            if callable(message_handler):
                message_handler(message)
            else:
                self.on_request(command, message)
        else:
            self.on_response(message)

    def create_response(self, command: str, message: Message) -> Deferred:
        """Create response from request message."""
        raise NotImplementedError

    def do_response(self, message: Message) -> None:
        """
        Send response message to the client.
        Before sending additional message preparing required.
        So, `self.create_response` method do this work.
        """
        logger.debug("Sending response: {message}", message=message)
        response = message.create_answer()
        self.transport.write(response)

    def init_request(self, command: str, app_id: str) -> Message:
        """Init creation request message."""
        message = Message(self._dictionary)
        message.new(command, app_id)
        return message

    def create_request(self, command: str,  message: Message) -> Deferred:
        """Create request message."""
        raise NotImplementedError

    def do_request(self, message: Message,
                   timeout: Optional[int] = None) -> None:
        """
        Send request message to the client.
        Before sending additional message preparing required.
        """
        deferred = Deferred()
        timeout = timeout or self.request_timeout

        def on_timeout(failure, timeout_):
            logger.error('Request timed out, no response was received '
                         'in {timeout} sec', timeout=timeout_)
            del self._pending_requests[self._hop_by_hop]

        # noinspection PyTypeChecker
        deferred.addTimeout(timeout, reactor, on_timeout)

        message.hdr.hopbyhop = self._hop_by_hop
        self._hop_by_hop += 1

        request = message.create_request()
        self.transport.write(request)

        self._pending_requests[self._hop_by_hop] = PendingRequest(message, deferred)

    def emit_request(self, command: str, app_id: str,
                     session_id: Optional[str] = None,
                     timeout: Optional[int] = None) -> None:
        """Emit server request."""
        logger.info("Emitting request: {command}, {app_id}",
                    command=command, app_id=app_id)
        message = self.init_request(command, app_id)
        method_name = "create_%s_request" % self._command_name_normalized(command)
        request_builder_method = getattr(self, method_name, None)
        if session_id is None:
            session_id = int(time.time())  # Not by RFC, but close enough
        message.encode("Session-Id", session_id)
        if request_builder_method is not None:
            d = request_builder_method(message)
        else:
            d = self.create_request(command, message)
        d.addCallback(lambda _: self.do_request(message, timeout))

    def do_forward(self, message: Message) -> None:
        """Message may be proxied, relayed, or redirected."""
        # logger.info("Forward message: {message}", message=message)
        # message.encode("Route-Record", config.HOST_ID)
        # request = message.create_request()
        raise NotImplementedError("Message forwarding not implemented on the node")

    def on_request(self, command: str, message: Message) -> None:
        """
        Message handler for all request commands except those that
        have personal handler.

        Personal request message handler name format:
            Capabilities-Exchange -> on_capabilities_exchange
            Registration-Termination -> on_registration_termination
            ...
        """
        raise NotImplementedError

    def on_response(self, message: Message) -> None:
        """Message is answer for the request."""
        pending_request: PendingRequest
        pending_request = self._pending_requests[message.hdr.hopbyhop]
        del self._pending_requests[message.hdr.hopbyhop]
        pending_request.deferred.callback(None)

    def on_error(self) -> None:
        """Errors handler."""
        raise NotImplementedError


class DiameterProtocol(BaseDiameterProtocol):
    """Diameter protocol."""

    def _create_response(self, command: str, message: Message) -> Deferred:
        method_name = "create_%s_response" % self._command_name_normalized(command)
        response_builder_method = getattr(self, method_name, None)
        if response_builder_method is not None:
            return response_builder_method(message)
        return self.create_response(command, message)

    @inlineCallbacks
    def create_response(self, command: str, message: Message) -> Deferred:
        """
        Create response from request message.
        Building response will may need for doing request on data storage.
        So, it may be done in a way something like this:
            res = yield self._storage_method(cmd)()
        """
        yield

    @inlineCallbacks
    def create_request(self, command: str, message: Message) -> Deferred:
        """
        Create request message.
        Building request will may need for doing request on data storage.
        So, it may be done in a way something like this:
            res = yield self._storage_method(cmd)()
        """
        yield

    def on_request(self, command: str, message: Message) -> None:
        """
        Message handler for all request commands except those that
        have personal handler.

        Personal request message handler name format:
            Capabilities-Exchange -> on_capabilities_exchange
            Registration-Termination -> on_registration_termination
            ...
        """
        d = self._create_response(command, message)
        d.addCallback(lambda _: self.do_response(message))

    def on_error(self) -> None:
        """Errors handler."""
        pass


class DummyDiameterProtocol(BaseDiameterProtocol):
    """Diameter dummy protocol. For test purposes only."""

    storage = MockStorage()

    @inlineCallbacks
    def create_response(self, command: str, message: Message) -> Deferred:
        """
        Create response from request message.
        Building response will may need for doing request on data storage.
        So, it may be done in a way something like this:
            res = yield self._storage_method(cmd)()
        """
        yield

    @inlineCallbacks
    def create_request(self, command: str, message: Message) -> Deferred:
        """
        Create request message.
        Building request will may need for doing request on data storage.
        So, it may be done in a way something like this:
            res = yield self._storage_method(cmd)()
        """
        yield

    def on_request(self, command: str, message: Message) -> None:
        """
        Message handler for all request commands except those that
        have personal handler.

        Personal request message handler name format:
            Capabilities-Exchange -> on_capabilities_exchange
            Registration-Termination -> on_registration_termination
            ...
        """
        logger.debug("Command={command}, Message={message}",
                     command=command, message=message)

    def on_error(self) -> None:
        """Errors handler."""
        logger.failure("Something went wrong")


class BillingDiameterProtocol(DiameterProtocol):
    storage = BillingStorage()


class DiameterFactory(Factory):
    protocol = DiameterProtocol


if __name__ == "__main__":
    host = config.HOST
    port = config.PORT

    # noinspection PyUnresolvedReferences
    reactor.listenTCP(port, DiameterFactory(), interface=host)
    logger.info("Started DIAMETER server on {host}:{port}",
                host=host, port=port)
    # noinspection PyUnresolvedReferences
    reactor.run()
