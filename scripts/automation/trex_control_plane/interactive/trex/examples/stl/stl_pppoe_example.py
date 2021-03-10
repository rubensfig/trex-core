#!/usr/bin/python
from __future__ import print_function

import stl_path
from trex.stl.api import *
from trex.common.services.trex_service_pppoe import ServicePPPOE

from functools import partial

try:
    input = raw_input
except NameError:
    pass

wait_for_key = input


def random_mac(count):
    i = 0
    macs = []
    for i in range(count):
        macs.append("02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)))
    return macs

def random_mac_range(count):
    return [random_mac() for _ in range(count)]


class PPPoETest(object):
    def __init__(self, port):
        self.port = port
        self.c = STLClient()
        # self.c.set_verbose("")

    def run(self, count):

        try:
            self.c.connect()
            self.c.reset(
                ports=self.port
            )  # Force acquire ports, stop the traffic, remove all streams and clear stats
            self.c.set_port_attr(self.port, promiscuous=True)
            self.ctx = self.c.create_service_ctx(port=self.port)
            self.capture_id = self.c.start_capture(tx_ports=0, rx_ports=0, mode="fixed", limit=50000)

            # create clients
            clients = self.setup(count)
            if not clients:
                print("\nno clients have sucessfully registered...exiting...\n")
                self.c.stop_capture(self.capture_id["id"], "/tmp/port_0_txrx.pcap")
                exit(1)

            self.c.stop_capture(self.capture_id["id"], "/tmp/port_0_txrx_setup.pcap")
            self.c.set_service_mode(
                ports=self.port, enabled=False
            )  # enables service mode on port = Rx packets not ignored

            # inject traffic
            self.inject(clients)

            # teardown - release clients
            self.teardown(clients)

        except STLError as e:
            print(e)
            exit(1)

        finally:
            self.c.disconnect()

    def setup(self, count):
        # phase one - service context
        # create PPPoE clients
        self.c.set_service_mode(
            ports=self.port, enabled=True
        )  # enables service mode on port = Rx packets not ignored
        clients = self.create_pppoe_clients(count)
        if not clients:
            return

        return clients

    def inject(self, clients):
        print("\n\nPress Return to generate high speed traffic from all clients...")
        wait_for_key()

        print(
            "\n*** step 4: generating UDP traffic from {} clients ***\n".format(
                len(clients)
            )
        )

        streams = []
        for client in clients:
            record = client.get_record()
            base_pkt = (
                Ether(src=record.client_mac, dst=record.server_mac)
                / Dot1AD(vlan=record.s_tag)
                / Dot1Q(vlan=record.c_tag)
                / PPPoE(sessionid=record.sid)
                / PPP(proto="Internet Protocol version 4")
                / IP(src=record.client_ip, dst="8.8.8.8")
                / UDP()
            )
            pkt = STLPktBuilder(pkt=base_pkt, vm=[])

            streams.append(STLStream(packet=pkt, mode=STLTXCont(pps=1000)))

        self.c.add_streams(ports=self.port, streams=streams)
        # self.c.start(ports = self.port, mult = '100%', synchronized=True)
        self.c.start(ports=self.port, mult="100%", synchronized=False)
        self.c.wait_on_traffic()

        print("\n*** Done ***\n")

    def teardown(self, clients):
        print("\n\nPress Return to release all DHCP clients...")
        wait_for_key()

        print(self.capture_id)
        self.c.stop_capture(self.capture_id, "/tmp/port_0_rx.pcap")
        try:
            # move back to service mode for releasing DHCPs
            self.c.set_service_mode(ports=self.port)
            self.release_dhcp_clients(clients)

        finally:
            self.c.set_service_mode(ports=self.port, enabled=False)

    def create_pppoe_clients(self, count):
        s_tag = 110
        c_tag = 100
        vlans = [(c_tag + i) for i in range(count)]
        vlan_mac = zip(vlans, random_mac(count))
        pppoe_clts = [
            ServicePPPOE(
                mac=j,
                verbose_level=ServicePPPOE.ERROR,
                s_tag=s_tag,
                c_tag=i,
            )
            for i,j  in vlan_mac
        ]

        # execute all the registered services
        print(
            "\n*** step 1: starting PPPoE acquire for {} clients ***\n".format(
                len(pppoe_clts)
            )
        )
        self.ctx.run(pppoe_clts)

        print("\n*** step 2: PPPoE acquire results ***\n")
        for dhcp in pppoe_clts:
            record = dhcp.get_record()
            print("client: MAC {0} - DHCP: {1}".format(dhcp.get_mac(), record))

        # filter those that succeeded
        bounded_pppoe_clts = [dhcp for dhcp in pppoe_clts if dhcp.state == "BOUND"]
        
        print("{0} clients bound out of {1} ".format(len(bounded_pppoe_clts), count))

        return bounded_pppoe_clts

    def release_dhcp_clients(self, clients):
        print(
            "\n*** step 5: starting DHCP release for {} clients ***\n".format(
                len(clients)
            )
        )
        self.ctx.run(clients)


def main():

    count = int(input("How many PPPoE clients to create: "))

    pppoe_test = PPPoETest(0)
    pppoe_test.run(count)


if __name__ == "__main__":
    main()
