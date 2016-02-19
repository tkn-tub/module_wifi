import logging
import random
import wishful_upis as upis
import wishful_agent as wishful_module
import subprocess
from wishful_framework.classes import exceptions
import inspect

__author__ = "Piotr Gawlowicz, Mikolaj Chwalisz, Zubow"
__copyright__ = "Copyright (c) 2015, Technische Universität Berlin"
__version__ = "0.1.0"
__email__ = "{gawlowicz, chwalisz, zubow}@tkn.tu-berlin.de"

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

    @wishful_module.bind_function(upis.net.get_info_of_associated_STAs)
    def get_info_of_associated_STAs(self):
        '''
            Returns information about associated STAs for a node running in AP mode
            tbd: use Netlink API
        '''

        self.log.debug("WIFI Module get info on associated clients on interface: {}".format(self.interface))

        try:
            [rcode, sout, serr] = self.run_command('iw dev ' + self.interface + ' station dump')

            # mac_addr -> stat_key -> list of (value, unit)
            res = {}
            sout_arr = sout.split("\n")

            for line in sout_arr:
                s = line.strip()
                if s == '':
                    continue
                if "Station" in s:
                    arr = s.split()
                    mac_addr = arr[1].strip()
                    res[mac_addr] = {}
                else:
                    arr = s.split(":")
                    key = arr[0].strip()
                    val = arr[1].strip()

                    arr2 = val.split()
                    val2 = arr2[0].strip()

                    if len(arr2) > 1:
                        unit = arr2[1].strip()
                    else:
                        unit = None

                    res[mac_addr][key] = (val2, unit)
            return res
        except Exception as e:
            fname = inspect.currentframe().f_code.co_name
            self.log.fatal("An error occurred in %s: %s" % (fname, e))
            raise exceptions.UPIFunctionExecutionFailedException(func_name=fname, err_msg=str(e))

    @wishful_module.bind_function(upis.net.get_inactivity_time_of_associated_STAs)
    def get_inactivity_time_of_associated_STAs(self):

        self.log.debug("WIFI Module get inactivity time of associated clients on interface: {}".format(self.interface))

        try:
            res = self.get_info_of_associated_STAs()

            rv = {}
            for mac_addr in res:
                inactive_time = res[mac_addr]['inactive time']
                self.log.info('%s -> %s' % (mac_addr, inactive_time))

                rv[mac_addr] = inactive_time

            # dict of mac_addr -> inactivity_time
            return rv
        except Exception as e:
            fname = inspect.currentframe().f_code.co_name
            self.log.fatal("An error occurred in %s: %s" % (fname, e))
            raise exceptions.UPIFunctionExecutionFailedException(func_name=fname, err_msg=str(e))

    def run_command(self, command):
        '''
            Method to start the shell commands and get the output as iterater object
        '''

        sp = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, err = sp.communicate()

        if False:
            if out:
                self.log.debug("standard output of subprocess:")
                self.log.debug(out)
            if err:
                self.log.debug("standard error of subprocess:")
                self.log.debug(err)

        if err:
            raise Exception("An error occurred in Dot80211Linux: %s" % err)

        return [sp.returncode, out, err]
