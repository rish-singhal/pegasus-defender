from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *

log = core.getLogger()


class PegasusQuarantine(object):
    """
    Quarantine all traffic from a malicious host in the network.
    """
    def __init__(self, connection):
        """
        Initialize the Quarantine module.

        Args:
            connection: An instance of the connection class.
        quarantine_hosts: A list of MAC addresses of hosts to quarantine.
        mac_to_port: A dictionary of MAC addresses and their associated
        HARD_TIMEOUT: The time in seconds to quarantine a host.
        """
        self.connection = connection
        connection.addListeners(self)
        self.quarantine_hosts = ["00:00:00:00:00:01"]
        self.mac_to_port = {}
        self.HARD_TIMEOUT = 30

    def resend_packet(self, packet_in, out_port):
        """
        Resend a packet to a given port.
        """
        msg = of.ofp_packet_out()
        msg.data = packet_in

        # Add an action to send to the specified port
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)

        # Send message to switch
        self.connection.send(msg)

    def inspect_packet(self, packet, packet_in):
        """
        Inspect a packet and determine if it should be quarantined.
        """
        self.mac_to_port[packet.src] = packet_in.in_port

        # If the source of the packet is in the quarantine list, quarantine
        if packet.src in self.quarantine_hosts:
            log.info(
              "Redirecting the packet back (quarantine host).."
              " source: %s", packet.src
            )
            msg = of.ofp_flow_mod()

            # Set fields to match received packet
            msg.match = of.ofp_match.from_packet(packet)
            msg.hard_timeout = self.HARD_TIMEOUT
            msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
            self.connection.send(msg)
        # If the source of the packet is not in the quarantine list,
        # forward the packet to the destination (and installs a flow rule)
        elif packet.dst in self.mac_to_port:
            log.info(
                "Installing flow .. source: %s, dest: %s" %
                (packet.src, packet.dst, )
            )

            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet)
            msg.actions.append(
                of.ofp_action_output(port=self.mac_to_port[packet.dst])
            )
            self.connection.send(msg)
        # Send the packet to all ports except the input port
        else:
            self.resend_packet(packet_in, of.OFPP_ALL)

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
        self.inspect_packet(packet, packet_in)

    @staticmethod
    def description():
        """
        Return a string describing the module.
        """
        return "Host Quarantine"
