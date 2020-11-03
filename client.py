#!/usr/bin/env python
from twisted.internet import reactor
from twisted.internet.protocol import ClientFactory

import config
import server
from utils.log import logger


__all__ = [
    "DiameterProtocol",
    "DummyDiameterProtocol",
    "BillingDiameterProtocol",
    "DiameterFactory",
]


class DiameterProtocol(server.DiameterProtocol):
    def connectionMade(self):
        super().connectionMade()
        logger.info("Connected.")
        self.send_test_message()

    def send_test_message(self):
        msg = b'\x01\x00\x02h\x80\x00\x01\t\x01\x00\x008\x00\x00\x03\xe9\x00\x00\x07\xd1\x00\x00\x01\x07@\x00\x00jtopon.s5.pgw01.reston.erc2.ericsson.epc.mnc120.mcc310.3gppnetwork.org;1;1322682238;310120000010780\x00\x00\x00\x00\x01\x02@\x00\x00\x0c\x01\x00\x008\x00\x00\x01\x08@\x00\x00Mtopon.s5.pgw01.reston.erc2.ericsson.epc.mnc120.mcc310.3gppnetwork.org\x00\x00\x00\x00\x00\x01(@\x00\x00)epc.mnc120.mcc310.3gppnetwork.org\x00\x00\x00\x00\x00\x01\x1b@\x00\x00\x18ehrpd.sprint.com\x00\x00\x01\x12@\x00\x00\x0c\x00\x00\x00\x02\x00\x00\x00\x01@\x00\x00=310120000010780@nai.epc.mnc120.mcc310.3gppnetwork.org\x00\x00\x00\x00\x00\x01\xe6\x00\x00\x00\x8c\x00\x00\x01\\@\x00\x00\x84\x00\x00\x01%@\x00\x00Mtopon.s5.pgw01.reston.erc2.ericsson.epc.mnc120.mcc310.3gppnetwork.org\x00\x00\x00\x00\x00\x01\x1b@\x00\x00)epc.mnc120.mcc310.3gppnetwork.org\x00\x00\x00\x00\x00\x00|@\x00\x00\x10\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\xed@\x00\x00\x0fr.ispsn\x00\x00\x00\x01\x1a@\x00\x00Mtopon.s5.pgw01.reston.erc2.ericsson.epc.mnc120.mcc310.3gppnetwork.org\x00\x00\x00'
        self.transport.write(msg)


class DummyDiameterProtocol(DiameterProtocol):
    storage = server.MockStorage()


class BillingDiameterProtocol(DiameterProtocol):
    storage = server.BillingStorage()


class DiameterFactory(ClientFactory):
    protocol = DiameterProtocol

    def clientConnectionLost(self, connector, reason):
        logger.warn("Lost connection. Reason: {reason}", reason=reason)

    def clientConnectionFailed(self, connector, reason):
        logger.warn("Connection failed. Reason: {reason}", reason=reason)


if __name__ == "__main__":
    host = config.HOST
    port = config.PORT

    # noinspection PyUnresolvedReferences
    reactor.connectTCP(host, port, DiameterFactory())
    # noinspection PyUnresolvedReferences
    reactor.run()
