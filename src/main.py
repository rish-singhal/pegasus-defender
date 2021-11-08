"""
This component is the main part for communication with
with the OpenFlow, and guards again possible adverserial attacks
"""
from pox.core import core

from pox.project.src.pegasus.common import Pegasus

log = core.getLogger()


def launch():
    """
    This function is the main function for the component
    """
    def start(event):
        """
        This function is attached with the listener when first
        switch connects to the controller
        """
        log.debug("Controlling %s" % (event.connection,))
        Pegasus(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start)
