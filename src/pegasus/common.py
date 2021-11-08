from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.project.src.pegasus.modules.hub import PegasusHub
from pox.project.src.pegasus.modules.switch import PegasusSwitch
from pox.project.src.pegasus.modules.firewall import PegasusFirewall
from pox.project.src.pegasus.modules.quarantine import PegasusQuarantine
from pox.project.src.pegasus.modules.http_blocker import PegasusHTTPBlocker
from pox.project.src.pegasus.modules.reflector_net import PegasusReflectorNet
from pox.project.src.pegasus.modules.ddos_entropy import\
    PegasusDDoSDefenderEntropy

log = core.getLogger()

# more modules can be added by just adding a new class to the list
modules = {
    1: PegasusHub,
    2: PegasusSwitch,
    3: PegasusFirewall,
    4: PegasusQuarantine,
    5: PegasusHTTPBlocker,
    6: PegasusReflectorNet,
    7: PegasusDDoSDefenderEntropy
}


class Pegasus(object):
    """
    The Pegasus class is the main class of the Pegasus project which parses
    the user input and calls the appropriate module.
    """
    def __init__(self, connection):
        opt = self.parse()
        select_module = modules.get(opt, None)
        select_module(connection)

    def parse(self):
        """ Takes input from the user to select one of the modules.
        """
        print("Select one of the given modules:")
        # Each module implements a description() staticmethod.
        for ind in modules:
            print(ind, ":", modules[ind].description())

        # Error handling done for the various possible input values
        while True:
            try:
                opt = int(input("> "))
                if opt not in range(1, len(modules) + 1):
                    raise ValueError
                break
            except ValueError:
                print(
                    "That was no valid option i.e "
                    "(1 <= opt <= %s) Try again..." % (len(modules) + 1,)
                )

        return opt
