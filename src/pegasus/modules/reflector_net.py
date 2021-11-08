from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.revent import *

log = core.getLogger()


class PegasusReflectorNet(object):
    """
    A PegasusReflectorNet object is created for each switch that connects.
    """
    def __init__(self, connection):
        """
        Initialize the PegasusReflectorNet object with
        1. connection: the connection to the switch
        2. blacklisted_ipaddrs: a list of ip addresses that should be
        redirected to the reflector port
        """
        self.connection = connection
        connection.addListeners(self)
        self.blacklisted_ipaddrs = ['10.0.0.1']
        self.REFLECT_TO_PORT = 65500

    def resend_packet(self, packet_in, out_port):
        """
        Instructs the switch to resend a packet that it had sent to us.
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
            msg.match.nw_src = IPAddr(addr)
            action = of.ofp_action_output(port=self.REFLECT_TO_PORT)
            msg.actions.append(action)

            self.connection.send(msg)
            log.info(
                "Redirecting all messages from ip address: %s to port %s"
                % (addr, self.REFLECT_TO_PORT)
            )

    def _handle_PacketIn(self, event):
        """
        Handles the event of a packet being sent to the controller.
        """
        packet = event.parsed   # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp   # The actual ofp_packet_in message.

        # hub:: send the packet to every other port other than the
        # input port
        self.resend_packet(packet_in, of.OFPP_ALL)

    @staticmethod
    def description():
        """
        Returns a string description of the module.
        """
        return "Reflector Net"
