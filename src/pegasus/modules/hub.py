from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()


class PegasusHub(object):
    """
    A PegasusDefence object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """
    def __init__(self, connection):
        """
        Initialize
        """
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

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
        return "Hub"
