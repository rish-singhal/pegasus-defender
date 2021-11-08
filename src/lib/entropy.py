import math

from pox.project.src.constants import DEFAULT_ENTROPY


class Entropy(object):
    def __init__(self):
        """
        Initialize the entropy object.
        """
        self.total_num_packets = dict()
        self.total_flow = 0
        self.change = False
        self._entropy = DEFAULT_ENTROPY

    def update(self, dest_ipaddr):
        """
        Update the entropy object.
        """
        self.total_num_packets[dest_ipaddr] = \
            self.total_num_packets.get(dest_ipaddr, 0) + 1

        self.total_flow += 1
        self.change = True

    @property
    def entropy(self):
        """
        Return the entropy value.
        """
        if self.change:
            self.calculate_entropy()
        return self._entropy

    def clear_up(self):
        """
        Clear the entropy object.
        """
        self.total_flow = 0
        self.change = False
        self._entropy = 0

    def calculate_entropy(self):
        """ Sum_i^n - P_i log P_i """
        self._entropy = 0.0
        for dest_ipaddr in self.total_num_packets:
            p_i = self.total_num_packets[dest_ipaddr] / self.total_flow
            self._entropy += -1 * p_i * math.log(p_i, 10)

        self.change = False
