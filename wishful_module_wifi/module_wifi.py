import os
import logging
import subprocess
import inspect
from scapy.all import *

# pip install -U -e git+https://github.com/wraith-wireless/PyRIC#egg=pyric
import pyric                           # pyric error (and ecode EUNDEF)
from pyric import pyw                  # for iw functionality
import pyric.utils.hardware as hw      # for chipset/driver
from pyric.utils.channels import rf2ch  # rf to channel conversion
from pyric.utils.channels import ch2rf  # rf to channel conversion

from pyroute2 import IW

import wishful_upis as upis
from wishful_agent.core import wishful_module
from wishful_agent.core import exceptions

__author__ = "Piotr Gawlowicz, Anatolij Zubow"
__copyright__ = "Copyright (c) 2015, Technische Universität Berlin"
__version__ = "0.1.0"
__email__ = "{gawlowicz, zubow}@tkn.tu-berlin.de"


@wishful_module.build_module
class WifiModule(wishful_module.AgentModule):
    def __init__(self):
        super(WifiModule, self).__init__()
        self.log = logging.getLogger('WifiModule')
        self.phyName = None
        self.phyIndex = None
        self.channel = None
        self.power = None

    @wishful_module.on_start()
    def my_start_function(self):
        found = False
        for card in pyw.phylist():
            if card[1] == self.device:
                found = True
                self.phyIndex = card[0]
                self.phyName = card[1]

        if not found:
            self.log.info("Device {} not found".format(self.device))
            # TODO: raise exception
        else:
            self.log.info("Device {} found, index: {}"
                          .format(self.phyName, self.phyIndex))

    def _get_my_ifaces(self):
        myWInterfaces = []
        for ifName in pyw.winterfaces():
            card = pyw.getcard(ifName)
            if card.phy == self.phyIndex:
                myWInterfaces.append(ifName)
        return myWInterfaces

    def _check_if_my_iface(self, ifaceName):
        if not pyw.iswireless(ifaceName):
            return False

        myIfaces = _get_my_ifaces()
        if ifaceName in myIfaces:
            return True

        return False

    def get_interfaces(self):
        ifaces = _get_my_ifaces()
        return ifaces

    def get_interface_info(self, ifaceName):
        if not self._check_if_my_iface():
            return False  # todo : raise exception
        dinfo = pyw.devinfo(interface)
        return dinfo

    def get_phy_info(self, ifaceName):
        if not self._check_if_my_iface():
            return False  # todo : raise exception
        dinfo = pyw.devinfo(interface)
        card = dinfo['card']
        pinfo = pyw.phyinfo(card)
        return pinfo

    def add_interface(self, ifaceName, mode):
        if ifaceName in pyw.winterfaces():
            return False

        iw = IW()
        mode2int = {'adhoc': 1,
                    'sta': 2,
                    'station': 2,
                    'managed': 2,
                    'ap': 3,
                    'ap_vlan': 4,
                    'wds': 5,
                    'monitor': 6,
                    'mesh_point': 7,
                    'p2p_client': 8,
                    'p2p_go': 9,
                    'p2p_device': 10,
                    'ocb': 11}

        modeInt = mode2int.get(mode, None)
        if modeInt is None:
            return False

        iw.add_interface(ifaceName, modeInt, None, 0)
        return True

    def delete_interface(self, ifaceName):
        if not self._check_if_my_iface(ifaceName):
            return False  # todo : raise exception
        card = pyw.getcard(ifaceName)  # get a card for this iface
        pyw.devdel(card)

    def set_interface_up(self, ifaceName):
        if not self._check_if_my_iface(ifaceName):
            return False  # todo : raise exception
        card = pyw.getcard(ifaceName)  # get a card for this iface
        pyw.up(card)
        pyw.unblock(card)  # turn off the softblock

        status = pyw.isblocked(card)
        self.log.info('Isblocked: %s' % str(status))
        ret = pyw.isup(card)
        return ret

    def set_interface_down(self, ifaceName):
        if not self._check_if_my_iface(ifaceName):
            return False  # todo : raise exception
        card = pyw.getcard(ifaceName)  # get a card for this iface
        pyw.down(card)
        return True

    def isconnected(self, ifaceName):
        if not self._check_if_my_iface(ifaceName):
            return False  # todo : raise exception
        card = pyw.getcard(ifaceName)  # get a card for this iface
        return pyw.isconnected(card)

    def disconnect(self, ifaceName):
        if not self._check_if_my_iface(ifaceName):
            return False  # todo : raise exception
        card = pyw.getcard(ifaceName)  # get a card for this iface
        pyw.disconnect(card)

    def getLinkInfo(self, interfaceName):
        if not self._check_if_my_iface(interfaceName):
            return False  # todo : raise exception
        card = pyw.getcard(interfaceName)  # get a card for this iface
        link = pyw.link(card)
        return link

    def scan_networks(self, interfaceName):
        try:
            cmd = 'iw dev ' + interfaceName + ' scan'
            [rcode, sout, serr] = self.run_command(cmd)
            return sout
        except Exception as e:
            self.log.fatal("An error occurred in Dot80211Linux: %s" % e)
            raise Exception("An error occurred in Dot80211Linux: %s" % e)

    @wishful_module.bind_function(upis.radio.set_power)
    def set_power(self, power_dBm, interface):
        self.log.info('Setting power on iface {}:{} to {}'
                      .format(interface, self.device, str(power_dBm)))

        try:
            if not self._check_if_my_iface():
                return False  # todo : raise exception
            w0 = pyw.getcard(interface)  # get a card for interface
            pyw.txset(w0, 'fixed', power_dBm)
            self.power = power_dBm
        except Exception as e:
            fname = inspect.currentframe().f_code.co_name
            self.log.fatal("An error occurred in %s: %s" % (fname, e))
            raise exceptions.UPIFunctionExecutionFailed(func_name=fname,
                                                        err_msg=str(e))
        return True

    @wishful_module.bind_function(upis.radio.get_power)
    def get_power(self, interface):
        self.log.debug("getting power of interface: {}".format(interface))
        if not self._check_if_my_iface():
            return False  # todo : raise exception
        else:
            w0 = pyw.getcard(interface)  # get a card
            self.power = pyw.txget(w0)
        return self.power

    @wishful_module.bind_function(upis.wifi.radio.set_channel)
    def set_channel(self, channel, interface):

        self.log.info('Setting channel for {}:{} to {}'
                      .format(interface, self.device, channel))
        try:
            if not self._check_if_my_iface():
                return False  # todo : raise exception
            w0 = pyw.getcard(interface)  # get a card for interface
            # check mode
            dinfo = pyw.devinfo(w0)
            if dinfo['mode'] == 'AP':
                # give new chanel to hostapd
                # hostapd requires frequency not channel
                freq = ch2rf(channel)
                control_socket_path = "xxx"
                beacon_periods = 5
                cmd = ('sudo hostapd_cli -p {} chan_switch {} {}'
                       .format(control_socket_path, beacon_periods, freq))
                self.run_command(cmd)
            else:
                # chw: channel width oneof {None|'HT20'|'HT40-'|'HT40+'}
                chw = None
                pyw.chset(w0, channel, chw)
                self.channel = channel
        except Exception as e:
            fname = inspect.currentframe().f_code.co_name
            self.log.fatal("An error occurred in %s: %s" % (fname, e))
            raise exceptions.UPIFunctionExecutionFailed(func_name=fname,
                                                        err_msg=str(e))
        return True

    @wishful_module.bind_function(upis.wifi.radio.get_channel)
    def get_channel(self, interface):
        self.log.info('Get channel for {}:{}'
                      .format(interface, self.device))
        if not self._check_if_my_iface():
            return False  # todo : raise exception
        else:
            w0 = pyw.getcard(interface)  # get a card
            self.channel = pyw.chget(w0)
        return self.channel

    @wishful_module.bind_function(upis.wifi.net.get_info_of_connected_devices)
    def get_info_of_connected_devices(self, interface):
        '''
            Returns information about associated STAs
            for a node running in AP mode
            tbd: use Netlink API
        '''

        self.log.info("WIFI Module get info on associated",
                      "clients on interface: {}".format(interface))

        try:
            [rcode, sout, serr] = self.run_command(
                'iw dev ' + interface + ' station dump')

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
            raise exceptions.UPIFunctionExecutionFailedException(
                func_name=fname, err_msg=str(e))

    @wishful_module.bind_function(
        upis.wifi.net.get_inactivity_time_of_connected_devices)
    def get_inactivity_time_of_connected_devices(self, iface):
        return self.get_entry_of_connected_devices('inactive time', iface)

    @wishful_module.bind_function(
        upis.wifi.net.get_avg_sigpower_of_connected_devices)
    def get_avg_sigpower_of_connected_devices(self, iface):
        return self.get_entry_of_connected_devices('signal avg', iface)

    @wishful_module.bind_function(
        upis.wifi.net.get_sigpower_of_connected_devices)
    def get_sigpower_of_connected_devices(self, iface):
        return self.get_entry_of_connected_devices('signal', iface)

    @wishful_module.bind_function(
        upis.wifi.net.get_tx_retries_of_connected_devices)
    def get_tx_retries_of_connected_devices(self, iface):
        return self.get_entry_of_connected_devices('tx retries', iface)

    @wishful_module.bind_function(
        upis.wifi.net.get_tx_packets_of_connected_devices)
    def get_tx_packets_of_connected_devices(self, iface):
        return self.get_entry_of_connected_devices('tx packets', iface)

    @wishful_module.bind_function(
        upis.wifi.net.get_tx_failed_of_connected_devices)
    def get_tx_failed_of_connected_devices(self, iface):
        return self.get_entry_of_connected_devices('tx failed', iface)

    @wishful_module.bind_function(
        upis.wifi.net.get_tx_bytes_of_connected_devices)
    def get_tx_bytes_of_connected_devices(self, iface):
        return self.get_entry_of_connected_devices('tx bytes', iface)

    @wishful_module.bind_function(
        upis.wifi.net.get_tx_bitrate_of_connected_devices)
    def get_tx_bitrate_of_connected_devices(self, iface):
        return self.get_entry_of_connected_devices('tx bitrate', iface)

    @wishful_module.bind_function(
        upis.wifi.net.get_rx_bytes_of_connected_devices)
    def get_rx_bytes_of_connected_devices(self, iface):
        return self.get_entry_of_connected_devices('rx bytes', iface)

    @wishful_module.bind_function(
        upis.wifi.net.get_rx_packets_of_connected_devices)
    def get_rx_packets_of_connected_devices(self, iface):
        return self.get_entry_of_connected_devices('rx packets', iface)

    @wishful_module.bind_function(
        upis.wifi.net.get_authorized_connected_device)
    def get_authorized_connected_device(self, iface):
        return self.get_entry_of_connected_devices('authorized', iface)

    @wishful_module.bind_function(
        upis.wifi.net.get_authenticated_connected_device)
    def get_authenticated_connected_device(self, iface):
        return self.get_entry_of_connected_devices('authenticated', iface)

    @wishful_module.bind_function(
        upis.wifi.net.get_used_preamble_connected_device)
    def get_used_preamble_connected_device(self, iface):
        return self.get_entry_of_connected_devices('preamble', iface)

    @wishful_module.bind_function(
        upis.wifi.net.get_mfp_connected_device)
    def get_mfp_connected_device(self, iface):
        return self.get_entry_of_connected_devices('MFP', iface)

    @wishful_module.bind_function(
        upis.wifi.net.get_wmm_wme_connected_device)
    def get_wmm_wme_connected_device(self, iface):
        return self.get_entry_of_connected_devices('WMM/WME', iface)

    @wishful_module.bind_function(
        upis.wifi.net.get_tdls_peer_connected_device)
    def get_tdls_peer_connected_device(self, iface):
        return self.get_entry_of_connected_devices('TDLS peer', iface)

    @wishful_module.bind_function(upis.wifi.net.connect_to_network)
    def connect_to_network(self, iface, ssid):
        self.log.info('Connecting via to AP with SSID: %s->%s' %
                      (str(iface), str(ssid)))

        cmd_str = 'sudo iwconfig ' + iface + ' essid ' + str(ssid)

        try:
            [rcode, sout, serr] = self.run_command(cmd_str)
        except Exception as e:
            fname = inspect.currentframe().f_code.co_name
            self.log.fatal("An error occurred in %s: %s" % (fname, e))
            raise exceptions.UPIFunctionExecutionFailedException(
                func_name=fname, err_msg=str(e))

        return True

    def getHwAddr(self, ifaceName):
        if not self._check_if_my_iface():
            return False  # todo : raise exception
        w0 = pyw.getcard(interface)  # get a card for interface
        mac = pyw.macget(w0)
        return mac

    def getIfaceIpAddr(self, ifaceName):
        if not self._check_if_my_iface():
            return False  # todo : raise exception
        w0 = pyw.getcard(interface)  # get a card for interface
        ip = pyw.inetget(w0)[0]
        return ip

    @wishful_module.bind_function(upis.net.gen_layer2_traffic)
    def gen_layer2_traffic(self, iface, num_packets,
                           pkt_interval, max_phy_broadcast_rate_mbps,
                           **kwargs):

        self.log.info('gen_layer2_traffic ... here 802.11()')

        ipdst = kwargs.get('ipdst')
        ipsrc = kwargs.get('ipsrc')

        # get my MAC HW address
        myMacAddr = self.getHwAddr(iface)
        dstMacAddr = 'ff:ff:ff:ff:ff:ff'

        if pkt_interval is not None:
            # generate with some packet interval
            if num_packets > 255:
                num_packets = 255

            data = (RadioTap() /
                    Dot11(type=2, subtype=0, addr1=dstMacAddr,
                          addr2=myMacAddr, addr3=myMacAddr) /
                    LLC() /
                    SNAP() /
                    IP(dst=ipdst, src=ipsrc, ttl=(1, num_packets)))
            sendp(data, iface=iface, inter=pkt_interval)

            return 1.0 / pkt_interval
        else:
            assert max_phy_broadcast_rate_mbps is not None

            use_tcpreplay = kwargs.get('use_tcpreplay')

            # craft packet to be transmitted
            payload = 'Z' * ipPayloadSize
            data = (RadioTap() /
                    Dot11(type=2, subtype=0, addr1=dstMacAddr,
                          addr2=myMacAddr, addr3=myMacAddr) /
                    LLC() /
                    SNAP() /
                    IP(dst=ipdst, src=ipsrc) /
                    payload)

            # send 10 packets backlogged
            now = datetime.now()
            if use_tcpreplay:
                # use tcprelay
                sendpfast(data, iface=iface, mbps=phyBroadcastMbps,
                          loop=num_packets, file_cache=True)
            else:
                piter = (len(data) * 8) / (phyBroadcastMbps * 1e6)
                sendp(data, iface=iface, loop=1, inter=piter,
                      realtime=True, count=num_packets, verbose=0)

            delta = datetime.now() - now
            myDelta = delta.seconds + delta.microseconds / 1000000.0
            # calc achieved transmit data rate
            tx_frame_rate = (1.0 /
                             (myDelta / num_packets))

            self.log.info('gen80211L2LinkProbing(): tx_frame_rate=%d' %
                          int(tx_frame_rate))

            return tx_frame_rate

    @wishful_module.bind_function(upis.net.sniff_layer2_traffic)
    def sniff_layer2_traffic(self, iface, sniff_timeout, **kwargs):

        self.log.info('sniff layer 2 traffic ... here 802.11')

        # some additional filtering ...todo!!!!!!!
        ipdst = kwargs.get('ipdst')
        ipsrc = kwargs.get('ipsrc')

        rx_pkts = {}
        rx_pkts['res'] = 0

        def ip_monitor_callback(pkt):
            if IP in pkt and pkt[IP].src == ipsrc and pkt[IP].dst == ipdst:
                rx_pkts['res'] = rx_pkts['res'] + 1
                # return pkt.sprintf("{IP:%IP.src% -> %IP.dst% -> %IP.ttl%\n}")

        sniff(iface=iface, prn=ip_monitor_callback, timeout=sniff_timeout)

        numRxPkts = rx_pkts['res']
        self.log.info('sniff80211L2LinkProbing(): rxpackets= %d' % numRxPkts)
        return numRxPkts

    @wishful_module.bind_function(upis.net.inject_frame)
    def inject_frame(self, iface, frame, is_layer_2_packet,
                     tx_count=1, pkt_interval=1):
        self.log.debug("Inject frame".format())

        if is_layer_2_packet:
            sendp(frame, iface=iface, inter=pkt_interval,
                  realtime=True, count=tx_count, verbose=0)
        else:
            send(frame, iface=iface, inter=pkt_interval,
                 realtime=True, count=tx_count, verbose=0)

        return True

    @wishful_module.bind_function(upis.wifi.net.disconnect_device)
    def disconnect_device(self, iface, sta_mac_addr):
        """
        Send a disaccociation request frame
        to a client STA associated with this AP.
        tbd: what is -p ?? Please simplify
        """

        exec_file = str(os.path.join(
            self.getPlatformPathHandover())) + '/hostapd_cli'
        args = '-p /tmp/hostapd-' + iface + ' disassociate'

        command = exec_file + ' ' + args + ' ' + sta_mac_addr
        self.log.debug('Disassociate STA %s on iface %s' %
                       (sta_mac_addr, iface))
        self.log.debug('exe: %s' % command)

        try:
            [rcode, sout, serr] = self.run_command(command)
            return sout
        except Exception as e:
            fname = inspect.currentframe().f_code.co_name
            self.log.fatal("An error occurred in %s: %s" % (fname, e))
            raise exceptions.UPIFunctionExecutionFailedException(
                func_name=fname, err_msg=str(e))

    @wishful_module.bind_function(upis.wifi.net.remove_device_from_blacklist)
    def remove_device_from_blacklist(self, iface, sta_mac_addr):
        """
        Unblacklist a given STA in the AP,
        i.e. the STA is able to associate with this AP afterwards.
        tbd: what is -p ?? Please simplify
        """

        exec_file = str(os.path.join(
            self.getPlatformPathHandover())) + '/hostapd_cli'
        args = '-p /tmp/hostapd-' + iface + ' unblacklist_sta'

        command = exec_file + ' ' + args + ' ' + sta_mac_addr
        self.log.debug('exe: %s' % command)
        self.log.debug('Unblacklist node %s on iface %s' %
                       (sta_mac_addr, iface))

        try:
            [rcode, sout, serr] = self.run_command(command)
            return sout
        except Exception as e:
            fname = inspect.currentframe().f_code.co_name
            self.log.fatal("An error occurred in %s: %s" % (fname, e))
            raise exceptions.UPIFunctionExecutionFailedException(
                func_name=fname, err_msg=str(e))

    @wishful_module.bind_function(upis.wifi.net.add_device_to_blacklist)
    def add_device_to_blacklist(self, iface, sta_mac_addr):
        """
        Blacklist a given STA in the AP, i.e. any request
        for association by the STA will be ignored by the AP.
        tbd: what is -p ?? Please simplify
        """

        exec_file = str(os.path.join(
            self.getPlatformPathHandover())) + '/hostapd_cli'
        args = '-p /tmp/hostapd-' + iface + ' blacklist_sta'

        command = exec_file + ' ' + args + ' ' + sta_mac_addr
        self.log.debug('Blacklist node %s on iface %s' % (sta_mac_addr, iface))
        self.log.debug('exec %s' % command)

        try:
            [rcode, sout, serr] = self.run_command(command)
            return sout
        except Exception as e:
            fname = inspect.currentframe().f_code.co_name
            self.log.fatal("An error occurred in %s: %s" % (fname, e))
            raise exceptions.UPIFunctionExecutionFailedException(
                func_name=fname, err_msg=str(e))

    @wishful_module.bind_function(upis.wifi.net.register_new_device)
    def register_new_device(self, iface, sta_mac_addr):
        """
        Register a new STA within the AP,
        i.e. afterwards the STA is able to exchange data frames.
        tbd: consider client capabilities
        """

        self.log.debug('Add new STA %s on iface %s' % (sta_mac_addr, iface))

        exec_file = str(os.path.join(
            self.getPlatformPathHandover())) + '/hostapd_cli'

        self.log.debug('exec path: %s' % exec_file)

        try:
            cmd = "{} -p /tmp/hostapd-{}  new_sta {}".format(exec_file,
                                                             iface,
                                                             sta_mac_addr)
            [rcode, sout, serr] = self.run_command(cmd)
            return sout
        except Exception as e:
            fname = inspect.currentframe().f_code.co_name
            self.log.fatal("An error occurred in %s: %s" % (fname, e))
            raise exceptions.UPIFunctionExecutionFailedException(
                func_name=fname, err_msg=str(e))

    @wishful_module.bind_function(
        upis.wifi.net.trigger_channel_switch_in_device)
    def trigger_channel_switch_in_device(self, iface, sta_mac_addr,
                                         target_channel, serving_channel,
                                         **kwargs):
        """
        Transmit Channel Switch Announcement
        (CSA) beacon to the given STA.
        """

        bssid = kwargs.get('bssid')
        self.log.debug('Sending CSA to {} on iface {}'
                       .format(sta_mac_addr, iface),
                       ' with BSSID {} switch STA to channel {}'
                       .format(bssid, str(target_channel)))

        # tbd: clean up this mess
        data1 = ('3bc0904f0000000064000100000542494741500',
                 '1088c129824b048606c0301')
        data2 = ('050400020000070c44452024081464051a84031a2d1a0c001bffff',
                 '0000000000000000000001000000000000000000003d162c000400',
                 '0000000000000000000000000000000000007f0800000000000000',
                 '40dd180050f2020101800003a4000027a4000042435d0062322e00',
                 'dd06aaaaaa3f4325dd14aaaaaa8020544b4e2d4c6f57532d537973',
                 '74656ddd06aaaaaa215a01250300')
        beacon = (RadioTap() /
                  Dot11(type=0, subtype=8, addr1=sta_mac_addr,
                        addr2=bssid, addr3=bssid) /
                  binascii.unhexlify(
                  data1 + hex(serving_channel).replace("0x", "") + data2 +
                  hex(target_channel).replace("0x", "") + '00'))

        # tbd: do we really need this
        BEACON_ARQ = 3
        for ii in range(BEACON_ARQ):
            # repetitive transmission
            sendp(beacon, iface=iface)
        return True

    #################################################
    # Helper functions
    #################################################

    def get_entry_of_connected_devices(self, key, iface):

        try:
            res = self.get_info_of_connected_devices(iface)

            rv = {}
            for mac_addr in res:
                value = res[mac_addr][key]
                self.log.info('%s -> %s' % (mac_addr, value))
                rv[mac_addr] = value

            # dict of mac_addr -> value
            return rv
        except Exception as e:
            fname = inspect.currentframe().f_code.co_name
            self.log.fatal("An error occurred in %s: %s" % (fname, e))
            raise exceptions.UPIFunctionExecutionFailedException(
                func_name=fname, err_msg=str(e))

    def run_command(self, command):
        '''
        Method to start the shell commands
        and get the output as iterater object
        '''

        sp = subprocess.Popen(command, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, shell=True)
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

        return [sp.returncode, out.decode("utf-8"), err.decode("utf-8")]

    def run_timeout_command(self, command, timeout):
        """
            Call shell-command and either return its output or kill it
            if it doesn't normally exit within timeout seconds and return None
        """
        cmd = command.split(" ")
        start = datetime.datetime.now()
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while process.poll() is None:
            time.sleep(0.1)
            now = datetime.datetime.now()
            if (now - start).seconds > timeout:
                os.kill(process.pid, signal.SIGKILL)
                os.waitpid(-1, os.WNOHANG)
                return process.stdout.read()
        return process.stdout.read()
