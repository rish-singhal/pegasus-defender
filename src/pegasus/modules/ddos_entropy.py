"""Implementing DDoS detection module based on the paper
Omar, T., Ho, A., & Urbina, B. Detection of DDoS in SDN Environment
Using Entropy-based Detection.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.recoco import Timer

from pox.project.src.constants import *
from pox.project.src.lib.entropy import Entropy

log = core.getLogger()


class PegasusDDoSDefenderEntropy(object):
    """ A PegasusDDoSDefenderEntropy object is created for
        each switch that connects.
    """
    def __init__(self, connection):
        """
        Initialize
        connection is the connection to the switch
        Entropy is the entropy object
        drop_ddos_packets is a boolean variable to indicate whether to drop
        packets or not
        """
        self.connection = connection
        connection.addListeners(self)
        self.Entropy = Entropy()
        self.drop_ddos_packets = False

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

    def _monitor_packet(self, packet, packet_in):
        """
        Count the number of packets going on (only IP_TYPE)
        """
        if packet.type not in [packet.IP_TYPE]:
            return

        dest_ipaddr = packet.payload.dstip
        print(
            "PacketIn type was IP_TYPE, with IP_addr %s "
            % str(dest_ipaddr)
        )

        # increment flow counter for destination ip address
        self.Entropy.update(str(dest_ipaddr))
        log.info("Total Entropy of the switch is %s" % self.Entropy.entropy)

        if self.Entropy.entropy < DDOS_ENTROPY_THRESHOLD:
            # start dropping packets as DDOS is detected
            log.info("DDoS detected, switching off all the connections")
            self.drop_ddos_packets = True
            self.Entropy.clear_up()
            Timer(10, self._handle_timer_complete)

    def _handle_timer_complete(self):
        """
        Handle the timer completion event
        """
        self.drop_ddos_packets = False

    def _handle_PacketIn(self, event):
        """
        Handles packet in messages from the switch.
        """
        packet = event.parsed  # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.

        if self.drop_ddos_packets is False:
            self._monitor_packet(packet, packet_in)
            self.resend_packet(packet_in, of.OFPP_ALL)

    @staticmethod
    def description():
        """
        Return a string description of the module.
        """
        return "DDoS Defender based on Entropy"
