from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.revent import *

from pox.project.src.constants import *

log = core.getLogger()


class PegasusHTTPBlocker(object):
    """
    A PegasusHTTPBlocker object is created for each switch that connects.
    """
    def __init__(self, connection):
        """
        blacklisted_ips is a list of IPs that are blocked by the HTTPBlocker
        """
        self.connection = connection
        connection.addListeners(self)
        self.blacklisted_ipaddrs = ['10.0.0.1']

    def resend_packet(self, packet_in, out_port):
        """
        Instructs the switch to resend a packet that it had sent to us
        out_port is the port the packet is to be sent to.
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
        # create a flow table modification message
        for addr in self.blacklisted_ipaddrs:
            msg = of.ofp_flow_mod()
            msg.match.tp_dst = HTTP_PORT
            msg.match.nw_proto = TCP_PROTOCOL
            msg.match.dl_type = IPV4_TYPE
            msg.match.nw_src = IPAddr(addr)
            self.connection.send(msg)
            log.info(
                "Blocking all HTTP packets from ip address: %s" % (addr,)
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
        # acts like hub otherwise:: send the packet to every other
        # port other than the input port
        self.resend_packet(packet_in, of.OFPP_ALL)

    @staticmethod
    def description():
        """
        Returns a string description of the module.
        """
        return "HTTP Blocker"
