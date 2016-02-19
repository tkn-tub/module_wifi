import logging
import random
import wishful_upis as upis
import wishful_agent as wishful_module

__author__ = "Piotr Gawlowicz, Mikolaj Chwalisz"
__copyright__ = "Copyright (c) 2015, Technische Universität Berlin"
__version__ = "0.1.0"
__email__ = "{gawlowicz, chwalisz}@tkn.tu-berlin.de"


@wishful_module.build_module
class WifiModule(wishful_module.AgentUpiModule):
    def __init__(self, agentPort=None):
        super(WifiModule, self).__init__(agentPort)
        self.log = logging.getLogger('wifi_module.main')
        self.interface = "wlan0"
        self.channel = 1
        self.power = 1


    @wishful_module.bind_function(upis.radio.set_channel)
    def set_channel(self, channel):
        self.log.debug("WIFI Module sets channel: {} on interface: {}".format(channel, self.interface))
        self.channel = channel
        return ["SET_CHANNEL_OK", channel, 0]


    @wishful_module.bind_function(upis.radio.get_channel)
    def get_channel(self):
        self.log.debug("WIFI Module gets channel of interface: {}".format(self.interface))
        return self.channel


    @wishful_module.bind_function(upis.radio.set_power)
    def set_power(self, power):
        self.log.debug("WIFI Module sets power: {} on interface: {}".format(power, self.interface))
        self.power = power
        return {"SET_POWER_OK_value" : power}


    @wishful_module.bind_function(upis.radio.get_power)
    def get_power(self):
        self.log.debug("WIFI Module gets power on interface: {}".format(self.interface))
        return self.power