from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.revent import *

log = core.getLogger()


class PegasusFirewall(object):
    """
    A PegasusFirewall object is created for each switch that connects.
    """
    def __init__(self, connection):
        """
        Initialize
        backlisted_mac_addrs: list of mac addresses to block
        backlisted_flows: list of pairs of mac addresses to block
        """
        self.connection = connection
        connection.addListeners(self)
        self.blacklisted_mac_addrs = ['00:00:00:00:00:03']
        self.blacklisted_flows = [('00:00:00:00:00:01',
                                   '00:00:00:00:00:02')]

    def resend_packet(self, packet_in, out_port):
        """
        "packet_in" is the ofp_packet_in object the switch had sent to the
        controller due to a table-miss.
        """
        msg = of.ofp_packet_out()
        msg.data = packet_in

        # Add an action to send to the specified port
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)

        # Send message to switch
        self.connection.send(msg)

    def _handle_ConnectionUp(self, event):
        """
        Handles the event of a switch connecting to the controller.
        """
        # Blocking the communication with the hosts
        for mac_addr in self.blacklisted_mac_addrs:
            # create a flow table modification message
            msg = of.ofp_flow_mod()
            msg.match.dl_src = EthAddr(mac_addr)

            # msg.actions == []: True
            # that is the packet will be dropped
            self.connection.send(msg)
            log.info(
                "Blocking incoming traffic flow from mac address: %s ...",
                mac_addr
            )

        # Blocking pairs of flows
        for mac_addr_src, mac_addr_dst in self.blacklisted_flows:
            msg = of.ofp_flow_mod()
            msg.match.dl_src = EthAddr(mac_addr_src)
            msg.match.dl_dst = EthAddr(mac_addr_dst)

            # msg.actions == []: True
            # that is the packet will be dropped
            self.connection.send(msg)
            log.info(
                "Blocking any communication from %s to %s ...",
                mac_addr_src,
                mac_addr_dst
            )

    def _handle_PacketIn(self, event):
        """
        Handles packet in messages from the switch.
        """
        packet = event.parsed  # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.

        # hub:: send the packet to every other port other than the
        # input port
        self.resend_packet(packet_in, of.OFPP_ALL)

    @staticmethod
    def description():
        """
        Returns a string description of the module.
        """
        return "Firewall"
