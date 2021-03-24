from scapy.layers.ppp import PPPoE, PPPoED
from scapy.layers.l2 import Ether
from .trex_pppoetag import *
from scapy.packet import NoPayload
from scapy.layers.ppp import *
from collections import namedtuple, OrderedDict

from ..trex_client import PacketBuffer

from .trex_service_fast_parser import FastParser

import struct

import pprint


class PPPOEParser(FastParser):

    # message types
    PADI = 0x9
    PADO = 0x7
    PADR = 0x19
    PADS = 0x65
    PADT = 0xA7

    def __init__(self):
        base_pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff")
            / Dot1Q(vlan=100)
            / Dot1Q(vlan=110)
            / PPPoED(version=1, type=1, code=self.PADI, sessionid=0, len=0)
            / PPPoED_Tags()
        )

        FastParser.__init__(self, base_pkt)

        self.add_field("Ethernet.dst", "dstmac")
        self.add_field("Ethernet.src", "srcmac")
        self.add_field("PPP over Ethernet Discovery.code", "code")
        self.add_field("PPP over Ethernet Discovery.sessionid", "sessionid")
        self.add_field(
            "PPPoE Tag List.tag_list",
            "tag_list",
            getter=self.get_tags,
            setter=self.set_tags,
        )

    def get_tags(self, pkt_bytes, info):
        # min length
        if len(pkt_bytes) < info["offset"]:
            return None

        options = pkt_bytes[info["offset"] :]

        opt = OrderedDict()
        index = 0

        # PPPoED Tag 0x0101 = Service-Name
        # Accel pppd expects a specific service name,
        # even if this is 00
        # 2 Bytes Tag | 1 Byte Padding | 1 Byte Val : 0101|00|00
        service_name = b"\x01\x01\x00\x00"  

        options += service_name
        tag = PPPoED_Tags(_pkt=options)
        return options

    def set_tags(self, pkt_bytes, info, options):
        for o in options:
            print(o)

        return pkt_bytes

    def disc(self, mac):
        """
        generates a PPPoE discovery packet
        """

        # generate a new packet
        obj = self.clone()
        obj.srcmac = mac

        return PacketBuffer(obj.raw())

    def req(self, srcmac, dstmac):
        """
        generate a new request packet
        """

        # generate a new packet
        obj = self.clone()
        obj.srcmac = srcmac
        obj.dstmac = dstmac
        obj.code = self.PADR

        return PacketBuffer(obj.raw())

    def release(self, client_mac, server_mac, session_id):
        """
        generate a release request packet
        """

        # generate a new packet
        obj = self.clone()

        obj = self.clone()
        obj.srcmac = client_mac
        obj.dstmac = server_mac
        obj.session_id = session_id
        obj.code = self.PADT

        return PacketBuffer(obj.raw())
