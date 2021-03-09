"""
PPPoE service implementation

Description:
    <FILL ME HERE>

How to use:
    <FILL ME HERE>
    
Author:
  Stanislav Zaikin

"""
from .MSCHAPv2 import *
from ...common.services.trex_service import Service, ServiceFilter
from .trex_pppoe_parser import PPPOEParser
from .trex_service_fast_parser import FastParser

from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from .trex_pppoetag import *
from .trex_pppoetag import _PPP_lcptypes
from scapy.layers.ppp import *
from ipaddress import IPv4Address

from collections import defaultdict
import random
import struct
import socket
import re


def ipv4_num_to_str(num):
    return socket.inet_ntoa(struct.pack("!I", num))


def ipv4_str_to_num(ipv4_str):
    return struct.unpack("!I", socket.inet_aton(ipv4_str))[0]


def bytes2mac(mac):
    return "{0:02x}:{1:02x}:{2:02x}:{3:02x}:{4:02x}:{5:02x}".format(
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )


class ServiceFilterPPPOE(ServiceFilter):
    """
    Service filter for PPPOE services
    """

    def __init__(self):
        self.services = defaultdict(list)

    def add(self, service):
        print("here {0}".format(service.get_mac()))
        self.services[service.get_mac()].append(service)

    def lookup(self, pkt):
        # correct MAC is enough to verify ownership
        mac = Ether(pkt).dst
        print( 'Looking up for packet with dstmac: {0}'.format(mac))
        return self.services.get(mac, [])

    def get_bpf_filter(self):
        return ""


################### internal ###################
class ServicePPPOE(Service):

    # PPPOE states
    INIT, SELECTING, REQUESTING, LCP, AUTH, IPCP, BOUND = range(7)

    def __init__(self, mac, verbose_level=Service.ERROR, s_tag=None, c_tag=None):

        # init the base object
        super(ServicePPPOE, self).__init__(verbose_level)

        self.xid = random.getrandbits(32)

        self.mac = mac
        self.mac_bytes = self.mac2bytes(mac)
        self.record = None
        self.state = "INIT"

        # Pkt queue
        self.pkt_queue = []

        # States for PPPoE
        self.session_id = 0

        # States for LCP
        self.lcp_our_sent = False
        self.lcp_our_negotiated = False
        self.lcp_peer_negotiated = False

        # States for IPCP
        self.ipcp_our_sent = False
        self.ipcp_our_negotiated = False
        self.ipcp_peer_negotiated = False

        # QinQ VLAN tags
        self.s_tag = s_tag
        self.c_tag = c_tag

        # IP Address
        self.ip = "192.151.0.1"

    def is_prom_required(self):
        return True

    def get_filter_type(self):
        return ServiceFilterPPPOE

    def get_mac(self):
        return self.mac

    def get_mac_bytes(self):
        return self.mac_bytes

    def mac2bytes(self, mac):
        if type(mac) != str or not re.match(
            "[0-9a-f]{2}([:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()
        ):
            self.err("invalid MAC format: {}".format(mac))

        return struct.pack("B" * 6, *[int(b, 16) for b in mac.split(":")])

    #########################  protocol state machines  #########################

    def run(self, pipe):

        # while running under 'INIT' - perform acquire
        if self.state == "INIT":
            return self._acquire(pipe)
        elif self.state == "BOUND":
            return self._release(pipe)

    def _acquire(self, pipe):
        """
        Acquire PPPOE lease protocol
        """

        # main state machine loop
        self.state = "INIT"
        self.record = None
        self.retries = 5

        while True:

            # INIT state
            if self.state == "INIT":

                self.retries -= 1
                if self.retries <= 0:
                    break

                print("PPPOE: {0} ---> PADI".format(self.mac))

                pkt = Ether(src=self.get_mac_bytes(), dst="ff:ff:ff:ff:ff:ff")
                if self.s_tag:
                    pkt = pkt / Dot1Q(vlan=self.s_tag)
                if self.c_tag:
                    pkt = pkt / Dot1Q(vlan=self.c_tag)
                padi = pkt / PPPoED(
                    version=1, type=1, code=PPPOEParser.PADI, sessionid=0, len=0
                )

                # send a discover message
                yield pipe.async_tx_pkt(padi)

                self.state = "SELECTING"
                continue

            # SELECTING state
            elif self.state == "SELECTING":

                # wait until packet arrives or timeout occurs
                pkts = yield pipe.async_wait_for_pkt(4)
                pkts = [pkt["pkt"] for pkt in pkts]

                # filter out the offer responses
                offers = []
                for pkt in pkts:
                    pars = PPPOEParser()
                    ret = pars.parse(pkt)

                    if ret.code == PPPOEParser.PADO:
                        offers.append(ret)

                if not offers:
                    print(
                        "PPPOE: {0} *** timeout on offers - retries left: {1}".format(
                            self.mac, self.retries
                        )
                    )
                    self.state = "INIT"
                    continue

                offer = offers[0]
                for i in offers:
                    print(offer.srcmac)

                print(
                    "PPPOE: {0} <--- PADO from '{1}'".format(
                        self.mac, bytes2mac(offer.srcmac)
                    )
                )
                self.ac_mac = bytes2mac(offer.srcmac)
                self.tags = offer.tag_list

                self.state = "REQUESTING"
                continue

            # REQUEST state
            elif self.state == "REQUESTING":
                self.retries = 5

                print("PPPOE: {0} ---> PADR".format(self.mac))

                padr = (
                    Ether(src=self.get_mac(), dst=self.ac_mac)
                    / Dot1Q(vlan=self.s_tag)
                    / Dot1Q(vlan=self.c_tag)
                    / PPPoED(
                        version=1, type=1, code=PPPOEParser.PADR, sessionid=0, len=45
                    )
                    / PPPoED_Tags(_pkt=self.tags)
                )
                # padr.tag_list = self.tags

                # send the request
                yield pipe.async_tx_pkt(padr)

                # wait for response
                pkts = yield pipe.async_wait_for_pkt(4)
                pkts = [pkt["pkt"] for pkt in pkts]

                # filter out the offer responses
                services = []
                for pkt in pkts:
                    pars = PPPOEParser()
                    servs = pars.parse(pkt)

                    if servs.code == PPPOEParser.PADS:
                        services.append(servs)

                if not services:
                    print(
                        "PPPOE: {0} *** timeout on ack - retries left: {1}".format(
                            self.mac, self.retries
                        )
                    )
                    self.state = "INIT"
                    continue

                # by default we choose the first one... usually there should be only one response
                service = services[0]
                self.session_id = service.sessionid

                print(
                    "PPPOE: {0} <--- PADS from AC '{1}' session_id: '{2}'".format(
                        self.mac, bytes2mac(service.srcmac), self.session_id
                    )
                )
                self.state = "LCP"

                continue

            elif self.state == "LCP":

                # send the request
                if not self.lcp_our_negotiated:
                    print("PPPOE: {0} ---> LCP CONF REQ".format(self.mac))
                    lcp_req = (
                        Ether(src=self.get_mac_bytes(), dst=self.ac_mac)
                        / Dot1Q(vlan=self.s_tag)
                        / Dot1Q(vlan=self.c_tag)
                        / PPPoE(sessionid=self.session_id)
                        / PPP(proto="Link Control Protocol")
                        / PPP_LCP_Configure(
                            code="Configure-Request",
                            options=[
                                PPP_LCP_MRU_Option(max_recv_unit=1492)
                                / PPP_LCP_Magic_Number_Option(magic_number=0x13371337)
                            ],
                        )
                    )
                    # lcp_req.show2()
                    yield pipe.async_tx_pkt(lcp_req)

                # wait for response
                pkts = yield pipe.async_wait_for_pkt(3)
                pkts = [pkt["pkt"] for pkt in pkts]
                pkts.extend(self.pkt_queue)

                for pkt in pkts:
                    lcp = Ether(pkt)
                    if PPP_LCP_Configure not in lcp:
                        self.log("Error, wrong type of packet, putting it into queue")
                        self.pkt_queue.append(pkt)
                        continue
                    if lcp[PPP_LCP_Configure].code == PPP_LCP.code.s2i["Configure-Ack"]:
                        print("PPPOE: {0} <--- LCP CONF ACK".format(self.mac))
                        self.lcp_our_negotiated = True
                    elif (
                        lcp[PPP_LCP_Configure].code
                        == PPP_LCP.code.s2i["Configure-Request"]
                    ):
                        print("PPPOE: {0} <--- LCP CONF REQ".format(self.mac))
                        lcp[PPP_LCP_Configure].code = PPP_LCP.code.s2i["Configure-Ack"]
                        lcp[Ether].src = self.mac
                        lcp[Ether].dst = self.ac_mac
                        # lcp.show()
                        print("PPPOE: {0} ---> LCP CONF ACK".format(self.mac))
                        yield pipe.async_tx_pkt(lcp)
                        self.lcp_peer_negotiated = True

                if self.lcp_our_negotiated and self.lcp_peer_negotiated:
                    self.state = "AUTH"

                continue
            elif self.state == "AUTH":
                print("PPPOE: {0} <--- CHAP ".format(self.mac))

                # wait for response
                pkts = yield pipe.async_wait_for_pkt(3)
                pkts = [pkt["pkt"] for pkt in pkts]

                challenge_id = 0
                value = 0
                for pkt in pkts:
                    chap = Ether(pkt)
                    if (
                        chap[PPP_CHAP_ChallengeResponse].code
                        == PPP_CHAP.code.s2i["Challenge"]
                    ):
                        challenge_id = chap[PPP_CHAP_ChallengeResponse].id
                        value = chap[PPP_CHAP_ChallengeResponse].value

                crypto = MSCHAPv2Crypto(
                    challenge_id, value, value, b"testing", "password"
                )  # USER DEFAULTS = testing/ password
                print(crypto.challenge_response())
                mschap_pkt = MSCHAPv2Packet(2)
                mschap_pkt.ms_chap_id = challenge_id
                mschap_pkt.challenge = value
                mschap_pkt.response = crypto.challenge_response()
                mschap_pkt.name = b"testing"

                # send the request
                print("PPPOE: {0} ---> CHAP CHALLENGE RESPONSE ".format(self.mac))
                lcp_req = (
                    Ether(src=self.get_mac_bytes(), dst=self.ac_mac)
                    / Dot1Q(vlan=self.s_tag)
                    / Dot1Q(vlan=self.c_tag)
                    / PPPoE(sessionid=self.session_id)
                    / PPP(proto="Challenge Handshake Authentication Protocol")
                    / PPP_CHAP_ChallengeResponse(_pkt=mschap_pkt.__bytes__())
                )

                # lcp_req.show()
                yield pipe.async_tx_pkt(lcp_req)

                # wait for response
                pkts = yield pipe.async_wait_for_pkt(3)
                pkts = [pkt["pkt"] for pkt in pkts]

                self.auth_negotiated = False
                print("PPPOE: {0} <--- CHAP SUCCESS ".format(self.mac))
                for pkt in pkts:
                    chap_success = Ether(pkt)
                    # chap_success.show()
                    if PPP_CHAP not in chap_success:
                        self.pkt_queue.append(pkt)
                        continue
                    if chap_success[PPP_CHAP].code == PPP_CHAP.code.s2i["Success"]:
                        self.auth_negotiated = True

                if self.auth_negotiated == True:
                    self.state = "IPCP"

            elif self.state == "IPCP":
                # send the request
                if not self.ipcp_our_negotiated:
                    print("PPPOE: {0} ---> IPCP CONF REQ".format(self.mac))
                    ipcp_req = (
                        Ether(src=self.get_mac_bytes(), dst=self.ac_mac)
                        / Dot1Q(vlan=self.s_tag)
                        / Dot1Q(vlan=self.c_tag)
                        / PPPoE(sessionid=self.session_id)
                        / PPP(proto="Internet Protocol Control Protocol")
                        / PPP_IPCP(
                            code="Configure-Request",
                            options=[PPP_IPCP_Option_IPAddress(data=self.ip)],
                        )
                    )
                    # ipcp_req.show()
                    yield pipe.async_tx_pkt(ipcp_req)

                # wait for response
                pkts = yield pipe.async_wait_for_pkt(3)
                pkts = [pkt["pkt"] for pkt in pkts]

                for pkt in pkts:
                    ipcp = Ether(pkt)
                    if PPP_IPCP not in ipcp:
                        print("Error, wrong type of packet, putting it into queue")
                        self.pkt_queue.append(pkt)
                        continue
                    if ipcp[PPP_IPCP].code == PPP_IPCP.code.s2i["Configure-Ack"]:
                        print("PPPOE: {0} <--- IPCP CONF ACK".format(self.mac))
                        self.ipcp_our_negotiated = True
                    elif ipcp[PPP_IPCP].code == PPP_IPCP.code.s2i["Configure-Request"]:
                        print("PPPOE: {0} <--- IPCP CONF REQ".format(self.mac))
                        for opt in ipcp[PPP_IPCP].options:
                            if isinstance(opt, PPP_IPCP_Option_IPAddress):
                                self.ac_ip = opt.data
                        ipcp[PPP_IPCP].code = PPP_IPCP.code.s2i["Configure-Ack"]
                        ipcp[Ether].src = self.mac
                        ipcp[Ether].dst = self.ac_mac
                        # ipcp.show()
                        print("PPPOE: {0} ---> IPCP CONF ACK".format(self.mac))
                        yield pipe.async_tx_pkt(ipcp)
                        self.ipcp_peer_negotiated = True
                    elif ipcp[PPP_IPCP].code == PPP_IPCP.code.s2i["Configure-Nak"]:
                        for opt in ipcp[PPP_IPCP].options:
                            if isinstance(opt, PPP_IPCP_Option_IPAddress):
                                self.ip = opt.data
                        print(
                            "PPPOE: {0} <--- IPCP CONF NAK, new IP: {1}".format(
                                self.mac, self.ip
                            )
                        )

                if self.ipcp_our_negotiated and self.ipcp_peer_negotiated:
                    self.state = "BOUND"
                continue
            elif self.state == "BOUND":

                # parse the offer and save it
                self.record = self.PPPOERecord(self)
                break

    def _release(self, pipe):
        """
        Release the PPPOE lease
        """
        self.log("PPPOE: {0} ---> RELEASING".format(self.mac))

        release_pkt = parser.release(
            self.xid,
            self.record.client_mac,
            ipv4_str_to_num(self.record.client_ip),
            self.record.server_mac,
            ipv4_str_to_num(self.record.server_ip),
        )

        yield pipe.async_tx_pkt(release_pkt)

        # clear the record
        self.record = None

    def get_record(self):
        """
        Returns a PPPOE record
        """
        return self.record

    class PPPOERecord(object):
        def __init__(self, parent):

            self.server_mac = parent.ac_mac
            self.client_mac = parent.mac
            self.server_ip = parent.ac_ip
            self.client_ip = parent.ip
            self.sid = parent.session_id
            self.s_tag = parent.s_tag
            self.c_tag = parent.c_tag

        def __str__(self):
            return "ip: {0}, server_ip: {1}".format(self.client_ip, self.server_ip)
