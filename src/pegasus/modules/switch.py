"""
This component is the main part for communication with
with the OpenFlow, and guards again possible adverserial attacks
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()


class PegasusSwitch(object):
    """
    A PegasusDefence object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """
    def __init__(self, connection):
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # Use this table to keep track of which ethernet address is on
        # which switch port (keys are MACs, values are ports).
        self.mac_to_port = {}

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

    def learn_addresses(self, packet, packet_in):
        """
        Learns the port for the source MAC address and adds it to the table.
        """
        # Learn the address for the incoming port
        self.mac_to_port[packet.src] = packet_in.in_port

        if packet.dst in self.mac_to_port:
            log.info(
                "Installing flow .. source: %s, dest: %s"
                % (packet.src, packet.dst, )
            )

            msg = of.ofp_flow_mod()
            # Set fields to match received packet
            msg.match = of.ofp_match.from_packet(packet)

            msg.actions.append(of.ofp_action_output(
                port=self.mac_to_port[packet.dst])
            )

            self.connection.send(msg)

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

        self.learn_addresses(packet, packet_in)

    @staticmethod
    def description():
        """
        Returns a string description of the module.
        """
        return "Switch"
