"""
PPPoE service implementation

Description:
    This script implements the PPPoE State Machine. This state machineis meant to be run
    with the TRex traffic generator. 

    The script is currently implementing:
        - PPPoE PADX packet exchanges
        - LCP negotiation
        - CHAP authentication
        - IPCP negotiation
        - Session termination

    The script currently is run with the intent of setting up PPPoE sessions to provide a 
    TRex app to test a dataplane with a certain number of clients. Each instance of this
    state machine only setups one one client, so having many clients must be handled from
    outside the script. 

    A hard limitation is the number of packets per second that can be queued for TX from 
    multiple clients. Currently there is a limit of 100 pps that can be queued. This has
    effects on the delays of sent packets, which will break can break provisioning, if the
    accel-ppp server has timeouts on the various states of client setup.

    After the client is bound and test is run, calling the run script again will
    free the client from the session by sending the PADT.

How to use:
    ServicePPPOE(
        mac=XX:XX:XX:XX:XX:XX,
        verbose_level=ServicePPPOE.ERROR,
        s_tag=100,
        c_tag=10,
        username='testing'
        password='password',
    )

    Create an instance of this Service Implementation by calling the above class creation, and run

    self.ctx = self.c.create_service_ctx(port=self.port)
    ...

    self.ctx.run(clients)

    
Authors:
  Adapted from Stanislav Zaikin, Rubens Figueiredo

"""
from radius_eap_mschapv2.MSCHAPv2 import MSCHAPv2Crypto, MSCHAPv2Packet
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
        # print("here {0}".format(service.get_mac()))
        self.services[service.get_mac()].append(service)

    def lookup(self, pkt):
        # correct MAC is enough to verify ownership
        mac = Ether(pkt).dst
        # print( 'Looking up for packet with dstmac: {0}'.format(mac))
        return self.services.get(mac, [])

    def get_bpf_filter(self):
        return ""


################### internal ###################
class ServicePPPOE(Service):

    # PPPOE states
    INIT, SELECTING, REQUESTING, LCP, AUTH, IPCP, BOUND = range(7)

    def __init__(
        self,
        mac,
        verbose_level=Service.ERROR,
        s_tag=None,
        c_tag=None,
        username="testing",
        password="password",
    ):

        # init the base object
        super(ServicePPPOE, self).__init__(verbose_level)

        self.xid = random.getrandbits(32)

        self.mac = mac
        self.mac_bytes = self.mac2bytes(mac)
        self.record = None
        self.state = "INIT"
        self.timeout = 1

        # Pkt queue
        self.pkt_queue = []

        # States for PPPoE
        self.session_id = 0

        # States for CHAP
        self.chap_got_challenge_id = False
        self.chap_challenge = False
        self.chap_challenge_id = 0
        self.chap_value = 0

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

        # Retries
        self.global_retries = 5
        self.per_state_retries = 3

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

    def reset_state_retries(self):
        self.per_state_retries = 3

    def handle_state_retries(self):
        if self.per_state_retries <= 0:
            return True

        self.per_state_retries -= 1
        return False

    def handle_global_retries(self):
        if self.global_retries <= 0:
            # Reset states for PPPoE
            self.session_id = 0

            # Reset states for CHAP
            self.chap_got_challenge_id = False
            self.chap_challenge = False
            self.chap_challenge_id = 0
            self.chap_value = 0

            # Reset states for LCP
            self.lcp_our_sent = False
            self.lcp_our_negotiated = False
            self.lcp_peer_negotiated = False

            # Reset states for IPCP
            self.ipcp_our_sent = False
            self.ipcp_our_negotiated = False
            self.ipcp_peer_negotiated = False

            return True

        self.global_retries -= 1
        return False

    #########################  protocol state machines  #########################

    def run(self, pipe):

        try:
            # while running under 'INIT' - perform acquire
            if self.state == "INIT":
                return self._acquire(pipe)
            else:
                return self._release(pipe)
        except ValueError:
            pass

    def _acquire(self, pipe):
        """
        Acquire PPPOE lease protocol
        """

        # main state machine loop
        self.state = "INIT"
        self.record = None

        while True:

            # INIT state
            if self.state == "INIT":
                if self.handle_global_retries():
                    break
                if self.handle_state_retries():
                    print("PPPOE {0}: {1} retry {2} ---> PADI".format(self.state, self.mac, self.global_retries))

                self.log("PPPOE: {0} ---> PADI".format(self.mac), level=Service.INFO)

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
                self.reset_state_retries()
                continue

            # SELECTING state
            elif self.state == "SELECTING":
                if self.handle_state_retries():
                    self.state = "INIT"
                    continue

                # wait until packet arrives or timeout occurs
                pkts_arr = yield pipe.async_wait_for_pkt(self.timeout)
                pkts = [pkt["pkt"] for pkt in pkts_arr]

                # filter out the offer responses
                offers = []
                for pkt in pkts:
                    pars = PPPOEParser()
                    ret = pars.parse(pkt)

                    if ret.code == PPPOEParser.PADO:
                        offers.append(ret)

                if not offers:
                    print(
                        "PPPOE - {0}: {1} *** timeout on offers - retries left: {2}".format(
                            self.state, self.mac, self.per_state_retries
                        )
                    )
                    continue

                offer = offers[0]

                self.log(
                    "PPPOE: {0} <--- PADO from '{1}'".format(
                        self.mac, bytes2mac(offer.srcmac)
                    ),
                    level=Service.INFO,
                )
                self.ac_mac = bytes2mac(offer.srcmac)
                self.tags = offer.tag_list

                # HACK wait for PADO
                pkts_arr = yield pipe.async_wait_for_pkt(0.2)

                self.state = "REQUESTING"
                self.reset_state_retries()
                continue
            # REQUEST state
            elif self.state == "REQUESTING":
                if self.handle_state_retries():
                    self.state = "INIT"
                    print("PPPOE - {0}: {1} resetting state".format(self.state, self.mac, self.per_state_retries))
                    continue

                self.log("PPPOE: {0} ---> PADR".format(self.mac), level=Service.INFO)

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
                pkts_arr = yield pipe.async_wait_for_pkt(self.timeout)
                pkts = [pkt["pkt"] for pkt in pkts_arr]

                # filter out the offer responses
                services = []
                for pkt in pkts:
                    servs = Ether(pkt)

                    if servs.code == PPPOEParser.PADS:
                        services.append(servs)

                if not services:
                    print(
                        "PPPOE {0}: {1} *** timeout on ack - retries left: {2}".format(
                            self.state, self.mac, self.per_state_retries
                        )
                    )
                    continue

                # by default we choose the first one... usually there should be only one response
                service = services[0]
                self.session_id = service.sessionid

                self.log(
                    "PPPOE: {0} <--- PADS from AC '{1}' session_id: '{2}'".format(
                        self.mac, service.src, self.session_id
                    ),
                    level=Service.INFO,
                )
                self.state = "LCP"
                self.reset_state_retries()

                continue
            elif self.state == "LCP":
                if self.handle_state_retries():
                    self.state = "INIT"
                    print("PPPOE - {0}: {1} resetting state".format(self.state, self.mac, self.per_state_retries))
                    continue

                if not self.lcp_peer_negotiated:
                    for pkt in pkts:
                        lcp = Ether(pkt)

                        if PPP_LCP_Configure not in lcp:
                            continue
                        if (
                            lcp[PPP_LCP_Configure].code
                            == PPP_LCP.code.s2i["Configure-Request"]
                        ):
                            self.log(
                                "PPPOE: {0} <--- LCP CONF REQ".format(self.mac),
                                level=Service.INFO,
                            )
                            lcp[PPP_LCP_Configure].code = PPP_LCP.code.s2i[
                                "Configure-Ack"
                            ]
                            lcp[Ether].src = self.mac
                            lcp[Ether].dst = self.ac_mac
                            # lcp.show()
                            self.log(
                                "PPPOE: {0} ---> LCP CONF ACK".format(self.mac),
                                level=Service.INFO,
                            )
                            yield pipe.async_tx_pkt(lcp)
                            self.lcp_peer_negotiated = True

                if not self.lcp_our_negotiated:
                    self.log(
                        "PPPOE: {0} ---> LCP CONF REQ".format(self.mac),
                        level=Service.INFO,
                    )
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
                pkts = yield pipe.async_wait_for_pkt(self.timeout)
                pkts = [pkt["pkt"] for pkt in pkts]

                for pkt in pkts:
                    lcp = Ether(pkt)

                    if PPP_LCP_Configure not in lcp:
                        continue
                    if lcp[PPP_LCP_Configure].code == PPP_LCP.code.s2i["Configure-Ack"]:
                        self.log(
                            "PPPOE: {0} <--- LCP CONF ACK".format(self.mac),
                            level=Service.INFO,
                        )
                        self.lcp_our_negotiated = True
                    elif (
                        lcp[PPP_LCP_Configure].code
                        == PPP_LCP.code.s2i["Configure-Request"]
                    ):
                        self.log(
                            "PPPOE: {0} <--- LCP CONF REQ".format(self.mac),
                            level=Service.INFO,
                        )
                        lcp[PPP_LCP_Configure].code = PPP_LCP.code.s2i["Configure-Ack"]
                        lcp[Ether].src = self.mac
                        lcp[Ether].dst = self.ac_mac
                        # lcp.show()
                        self.log(
                            "PPPOE: {0} ---> LCP CONF ACK".format(self.mac),
                            level=Service.INFO,
                        )
                        yield pipe.async_tx_pkt(lcp)
                        self.lcp_peer_negotiated = True

                if self.lcp_our_negotiated and self.lcp_peer_negotiated:
                    self.state = "AUTH"
                    self.reset_state_retries()

                continue
            elif self.state == "AUTH":
                if self.handle_state_retries():
                    self.state = "INIT"
                    print("PPPOE - {0}: {1} resetting state".format(self.state, self.mac, self.per_state_retries))
                    continue

                self.log("PPPOE: {0} <--- CHAP ".format(self.mac), level=Service.INFO)

                if not self.chap_challenge:
                    for pkt in pkts:
                        chap = Ether(pkt)

                        if (PPP_CHAP_ChallengeResponse) not in chap:
                            continue
                        if (
                            chap[PPP_CHAP_ChallengeResponse].code
                            == PPP_CHAP.code.s2i["Challenge"]
                        ):
                            self.chap_challenge_id = chap[PPP_CHAP_ChallengeResponse].id
                            self.chap_value = chap[PPP_CHAP_ChallengeResponse].value

                            self.chap_challenge = True
                            break

                if not self.chap_challenge:
                    # wait for response
                    pkts = yield pipe.async_wait_for_pkt(self.timeout)
                    pkts = [pkt["pkt"] for pkt in pkts]

                    print(
                        "PPPOE {0}: {1} *** timeout on auth - retries left: {2}".format(
                            self.state, self.mac, self.per_state_retries
                        )
                    )
                    continue

                crypto = MSCHAPv2Crypto(
                    self.challenge_id, self.value, self.value, b"testing", "password"
                )  # USER DEFAULTS = testing/ password
                mschap_pkt = MSCHAPv2Packet(2)
                mschap_pkt.ms_chap_id = self.chap_challenge_id
                mschap_pkt.challenge = self.chap_value
                mschap_pkt.response = crypto.challenge_response()
                mschap_pkt.name = b"testing"

                # send the response
                self.log(
                    "PPPOE: {0} ---> CHAP CHALLENGE RESPONSE ".format(self.mac),
                    level=Service.INFO,
                )
                chap_resp = (
                    Ether(src=self.get_mac_bytes(), dst=self.ac_mac)
                    / Dot1Q(vlan=self.s_tag)
                    / Dot1Q(vlan=self.c_tag)
                    / PPPoE(sessionid=self.session_id)
                    / PPP(proto="Challenge Handshake Authentication Protocol")
                    / PPP_CHAP_ChallengeResponse(_pkt=mschap_pkt.__bytes__())
                )

                # lcp_req.show()
                yield pipe.async_tx_pkt(chap_resp)

                # wait for response
                pkts = yield pipe.async_wait_for_pkt(self.timeout)
                pkts = [pkt["pkt"] for pkt in pkts]

                self.auth_negotiated = False
                self.log(
                    "PPPOE: {0} <--- CHAP SUCCESS ".format(self.mac), level=Service.INFO
                )
                for pkt in pkts:
                    chap_success = Ether(pkt)
                    # handles getting the ipcp packet before CHAP success, we can move on
                    if PPP_IPCP in chap_success:
                        self.auth_negotiated = True

                    if PPP_CHAP not in chap_success:
                        continue
                    if chap_success[PPP_CHAP].code == PPP_CHAP.code.s2i["Success"]:
                        self.auth_negotiated = True

                if self.auth_negotiated == True:
                    self.reset_state_retries()
                    self.state = "IPCP"

                continue
            elif self.state == "IPCP":
                if self.handle_state_retries():
                    self.state = "INIT"
                    print("PPPOE - {0}: {1} resetting state".format(self.state, self.mac, self.per_state_retries))
                    continue

                # send the request
                if not self.ipcp_our_negotiated:
                    self.log(
                        "PPPOE: {0} ---> IPCP CONF REQ".format(self.mac),
                        level=Service.INFO,
                    )
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

                if not self.ipcp_peer_negotiated:
                    for pkt in pkts:
                        ipcp = Ether(pkt)
                        if PPP_IPCP not in ipcp:
                            continue
                        if (
                            ipcp[PPP_IPCP].code
                            == PPP_IPCP.code.s2i["Configure-Request"]
                        ):
                            self.log(
                                "PPPOE: {0} <--- IPCP CONF REQ".format(self.mac),
                                level=Service.INFO,
                            )
                            for opt in ipcp[PPP_IPCP].options:
                                if isinstance(opt, PPP_IPCP_Option_IPAddress):
                                    self.ac_ip = opt.data
                            ipcp[PPP_IPCP].code = PPP_IPCP.code.s2i["Configure-Ack"]
                            ipcp[Ether].src = self.mac
                            ipcp[Ether].dst = self.ac_mac
                            # ipcp.show()
                            self.log(
                                "PPPOE: {0} ---> IPCP CONF ACK".format(self.mac),
                                level=Service.INFO,
                            )
                            yield pipe.async_tx_pkt(ipcp)
                            self.ipcp_peer_negotiated = True

                # wait for response
                pkts = yield pipe.async_wait_for_pkt(self.timeout)
                pkts = [pkt["pkt"] for pkt in pkts]

                for pkt in pkts:
                    ipcp = Ether(pkt)
                    if PPP_IPCP not in ipcp:
                        continue
                    if ipcp[PPP_IPCP].code == PPP_IPCP.code.s2i["Configure-Ack"]:
                        self.log(
                            "PPPOE: {0} <--- IPCP CONF ACK".format(self.mac),
                            level=Service.INFO,
                        )
                        self.ipcp_our_negotiated = True
                    elif ipcp[PPP_IPCP].code == PPP_IPCP.code.s2i["Configure-Nak"]:
                        for opt in ipcp[PPP_IPCP].options:
                            if isinstance(opt, PPP_IPCP_Option_IPAddress):
                                self.ip = opt.data
                        self.log(
                            "PPPOE: {0} <--- IPCP CONF NAK, new IP: {1}".format(
                                self.mac, self.ip
                            ),
                            level=Service.INFO,
                        )

                if self.ipcp_our_negotiated and self.ipcp_peer_negotiated:
                    self.reset_state_retries()
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
        pkt = Ether(src=self.get_mac_bytes(), dst=self.mac2bytes(self.ac_mac))
        if self.s_tag:
            pkt = pkt / Dot1Q(vlan=self.s_tag)
        if self.c_tag:
            pkt = pkt / Dot1Q(vlan=self.c_tag)
        padt = pkt / PPPoED(
            version=1, type=1, code=PPPOEParser.PADT, sessionid=self.session_id, len=0
        )

        yield pipe.async_tx_pkt(padt)

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
            self.state = parent.state

        def __str__(self):
            rpr = ""
            if self.client_ip:
                rpr = "STATE: {0} session id: {1}, ip: {2}, server_ip: {3}".format(self.state, self.sid, self.client_ip, self.server_ip)
            else:
                rpr = "STATE: {0} session id: {0}"
            return rpr
