# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation;
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#
# Created by Ahmed Khalid a.khalid@cs.ucc.ie and Jason Quinlan j.quinlan@cs.ucc.ie
# 03 November 2017 - version number 1.0.1

import socket
from struct import *
from subprocess import *
import threading

from mininet.clean import cleanup
from mininet.cli import CLI
from mininet.log import lg, LEVELS, info, debug, warn, error
from mininet.net import MininetWithControlNet
from mininet.node import ( Host, Node, CPULimitedHost, Controller, OVSController,
                           Ryu, NOX, RemoteController, findController,
                           DefaultController, NullController,
                           UserSwitch, OVSSwitch, OVSBridge,
                           IVSSwitch )
from mininet.nodelib import LinuxBridge
from mininet.link import Link, TCLink, OVSLink, TCULink
from mininet.topo import ( SingleSwitchTopo, LinearTopo,
                           SingleSwitchReversedTopo, MinimalTopo )
from mininet.topolib import TreeTopo, TorusTopo
from mininet.util import customClass, specialClass, splitArgs
from mininet.util import buildTopo
from functools import partial
from mininet.examples.cluster import ( MininetCluster, RemoteHost,
                                       RemoteOVSSwitch, RemoteLink,
                                       SwitchBinPlacer, RandomPlacer,
                                       ClusterCleanup )
from mininet.examples.clustercli import ClusterCLI


from optparse import OptionParser
import os
from tkMessageBox import showerror
import tkFont
import tkFileDialog
import tkSimpleDialog
import json
from distutils.version import StrictVersion
from mininet.term import makeTerm, cleanUpScreens
from mininet.net import Mininet, VERSION
from mininet.util import quietRun
import random
from threading import Thread
from Tkinter import *
import time
from cmath import pi
from math import atan2, sin, cos
from PIL import Image, ImageDraw
from PIL import ImageTk as itk
import Queue
from collections import OrderedDict

MININET_VERSION = re.sub(r'[^\d\.]', '', VERSION)
if StrictVersion(MININET_VERSION) > StrictVersion('2.0'):
    from mininet.node import IVSSwitch
MININAM_VERSION = "1.0.1"

# Fix setuptools' evil madness, and open up (more?) security holes
if 'PYTHONPATH' in os.environ:
    sys.path = os.environ[ 'PYTHONPATH' ].split( ':' ) + sys.path

Eth_Protocols = {'8':'IP', '1544':'ARP', '56710':'IPv6'}
IP_Protocols = {'1':'ICMP', '6':'TCP', '17':'UDP'}

TOPODEF = 'minimal'
TOPOS = {'minimal': MinimalTopo,
              'linear': LinearTopo,
              'reversed': SingleSwitchReversedTopo,
              'single': SingleSwitchTopo,
              'tree': TreeTopo,
              'torus': TorusTopo}

SWITCHDEF = 'default'
SWITCHES = {'user': UserSwitch,
                 'ovs': OVSSwitch,
                 'ovsbr': OVSBridge,
                 # Keep ovsk for compatibility with 2.0
                 'ovsk': OVSSwitch,
                 'ivs': IVSSwitch,
                 'lxbr': LinuxBridge,
                 'default': OVSSwitch}
SWITCHES_TYPES = [switch.__name__ for switch in SWITCHES.values()]

HOSTDEF = 'proc'
HOSTS = {'proc': Host,
              'rt': specialClass(CPULimitedHost, defaults=dict(sched='rt')),
              'cfs': specialClass(CPULimitedHost, defaults=dict(sched='cfs'))}
HOSTS_TYPES = ['Host', 'CPULimitedHost']

CONTROLLERDEF = 'default'
CONTROLLERS = {'ref': Controller,
                    'ovsc': OVSController,
                    'nox': NOX,
                    'remote': RemoteController,
                    'ryu': Ryu,
                    'default': DefaultController,  # Note: replaced below
                    'none': NullController}
CONTROLLERS_TYPES = [ctrlr.__name__ for ctrlr in CONTROLLERS.values()]

LINKDEF = 'default'
LINKS = {'default': Link,
              'tc': TCLink,
            'tcu': TCULink,
              'ovs': OVSLink}
LINKS_TYPES = ['Link', 'TCLink', 'OVSLink', 'TCULink']

LEGACY_TYPES = ['LegacyRouter', 'LinuxRouter', 'LegacySwitch']

FLOWTIMEDEF = 'Fast'
FLOWTIME = OrderedDict([('Very Slow', 40000),('Slow',20000),('Fast', 5000), ('Very Fast', 1000), ('Real Time', 1)])

LinkTime = 0.1

def version( *_args ):
    "Print Mininet and MiniNAM version and exit"
    print "Mininet: %s" % MININET_VERSION
    print "MiniNAM: %s" % MININAM_VERSION
    sys.exit()

def packetParser(packet):

    PacketInfo = {}
    PacketInfo['eth_protocol'] = None
    PacketInfo['srcMAC'] = None
    PacketInfo['dstMAC'] = None
    PacketInfo['s_addr'] = None
    PacketInfo['d_addr'] = None
    PacketInfo['ip_protocol'] = None
    PacketInfo['ttl'] = None
    PacketInfo['source_port'] = None
    PacketInfo['dest_port'] = None
    PacketInfo['sequence'] = None
    PacketInfo['data'] = None
    PacketInfo['icmp_type'] = None
    PacketInfo['code'] = None
    PacketInfo['checksum'] = None
    PacketInfo['length'] = None
    PacketInfo['protocol_type'] = None

    try:
        # parse ethernet header
        eth_length = 14
        eth_header = packet[:eth_length]

        eth = unpack('!6s6sH', eth_header)

        eth_protocol = socket.ntohs(eth[2])

        dstMAC = ':'.join('%02x' % ord(b) for b in packet[0:6])
        srcMAC = ':'.join('%02x' % ord(b) for b in packet[6:12])

        PacketInfo['srcMAC'] = str(srcMAC)
        PacketInfo['dstMAC'] = str(dstMAC)
        PacketInfo['eth_protocol'] = str(eth_protocol)

        # Parse IP packets, IP Protocol number = 8
        if eth_protocol == 8:
            # Parse IP header
            # take first 20 characters for the ip header
            ip_header = packet[eth_length:20 + eth_length]

            # now unpack them
            iph = unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            ihl = version_ihl & 0xF

            iph_length = ihl * 4

            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);

            PacketInfo['s_addr'] = s_addr
            PacketInfo['d_addr'] = d_addr
            PacketInfo['ip_protocol'] = str(protocol)
            PacketInfo['ttl'] = str(ttl)

            # TCP protocol
            if protocol == 6:
                t = iph_length + eth_length
                tcp_header = packet[t:t + 32]

                # now unpack them
                tcph = unpack('!HHLLBBHHHBBBBLL', tcp_header)

                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4
                TSVal =  tcph[13]


                h_size = eth_length + iph_length + tcph_length * 4
                # get data from the packet
                data = packet[h_size:]
                PacketInfo['source_port'] = source_port
                PacketInfo['dest_port'] = dest_port
                PacketInfo['sequence'] = sequence
                PacketInfo['acknowledgement'] = acknowledgement
                PacketInfo['TSVal'] = TSVal
                PacketInfo['data'] = data

            # ICMP Packets
            elif protocol == 1:
                u = iph_length + eth_length
                icmph_length = 4
                icmp_header = packet[u:u + 4]

                # now unpack them
                icmph = unpack('!BBH', icmp_header)

                icmp_type = icmph[0]
                code = icmph[1]
                checksum = icmph[2]

                h_size = eth_length + iph_length + icmph_length
                data_size = len(packet) - h_size

                # get data from the packet
                data = packet[h_size:]
                PacketInfo['icmp_type'] = str(icmp_type)
                PacketInfo['code'] = str(code)
                PacketInfo['checksum'] = str(checksum)
                PacketInfo['data'] = data

            # UDP packets
            elif protocol == 17:
                u = iph_length + eth_length
                udph_length = 8
                udp_header = packet[u:u + 8]

                # now unpack them
                udph = unpack('!HHHH', udp_header)

                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]

                h_size = eth_length + iph_length + udph_length
                data_size = len(packet) - h_size

                # get data from the packet
                data = packet[h_size:]
                PacketInfo['source_port'] = source_port
                PacketInfo['dest_port'] = dest_port
                PacketInfo['length'] = length
                PacketInfo['checksum'] = checksum
                PacketInfo['data'] = data
            # Other IP packet like IGMP can be parsed here.
            else:
                pass

        #Parse ARP packets
        elif eth_protocol == 1544:
            arp_header = packet[14:42]
            arph = unpack("!2sH1s1s2s6s4s6s4s", arp_header)
            s_addr = socket.inet_ntoa(arph[6])
            d_addr = socket.inet_ntoa(arph[8])
            protocol_type = arph[1]
            PacketInfo['s_addr'] = str(s_addr)
            PacketInfo['d_addr'] = str(d_addr)
            PacketInfo['protocol_type'] = protocol_type
        #Other EthPackets like IPv6 can be parsed here.
        else:
            pass

        return PacketInfo

    except:
        return PacketInfo

class PrefsDialog(tkSimpleDialog.Dialog):
    "Preferences dialog"

    def __init__(self, parent, title, prefDefaults):

        self.prefValues = prefDefaults

        tkSimpleDialog.Dialog.__init__(self, parent, title)

    def body(self, master):
        "Create dialog body"
        self.rootFrame = master

        # Field for displaying traffic flows
        Label(self.rootFrame, text="Display traffic flows in the network").grid(row=0, sticky=W)
        self.displayFlows = IntVar()
        self.cdisplayFlows = Checkbutton(self.rootFrame, variable=self.displayFlows)
        self.cdisplayFlows.grid(row=0, column=1, sticky=W)
        if self.prefValues['displayFlows'] == 0:
            self.cdisplayFlows.deselect()
        else:
            self.cdisplayFlows.select()

        # Field for displaying hosts along with network topology
        Label(self.rootFrame, text="Display hosts in the network:").grid(row=1, sticky=W)
        self.displayHosts = IntVar()
        self.cdisplayHosts = Checkbutton(self.rootFrame, variable=self.displayHosts)
        self.cdisplayHosts.grid(row=1, column=1, sticky=W)
        if self.prefValues['displayHosts'] == 0:
            self.cdisplayHosts.deselect()
        else:
            self.cdisplayHosts.select()

        # Field for Packet Flow Speed
        Label(self.rootFrame, text="Speed of Packet Flow").grid(row=2, sticky=W)
        self.flowTime = StringVar(self.rootFrame)
        self.flowTime.set(FLOWTIME.keys()[FLOWTIME.values().index(self.prefValues['flowTime'])])
        self.flowTimeMenu = OptionMenu(self.rootFrame, self.flowTime, *FLOWTIME.keys())
        self.flowTimeMenu.grid(row=2, column=1, sticky=W)

        # Field for Node Colors
        Label(self.rootFrame, text="Color Code Packets By:").grid(row=3, sticky=W)
        self.nodeColorsVar = StringVar(self.rootFrame)
        self.nodeColorsOption = OptionMenu(self.rootFrame, self.nodeColorsVar, "Source", "Destination", "None")
        self.nodeColorsOption.grid(row=3, column=1, sticky=W)
        self.nodeColorsVar.set(self.prefValues['nodeColors'])

        # Selection for color of packet type
        self.typeColorsFrame= LabelFrame(self.rootFrame, text='Colors for Packet Types', padx=5, pady=5)
        self.typeColorsFrame.grid(row=4, column=0, columnspan=2, sticky=EW)
        for i in range(3):
            self.typeColorsFrame.columnconfigure(i, weight=1)
        self.typeColors = self.prefValues['typeColors']

        # Selection of color for ARP
        Label(self.typeColorsFrame, text="ARP").grid(row=0, column=0, sticky=W)
        self.ARPColor = StringVar(self.typeColorsFrame)
        self.ARPColor.set(self.typeColors["ARP"])
        self.ARPColorMenu = OptionMenu(self.typeColorsFrame, self.ARPColor, "None", "Red", "Green", "Blue", "Purple")
        self.ARPColorMenu.grid(row=1, column=0, sticky=W)

        # Selection of color for TCP
        Label(self.typeColorsFrame, text="TCP").grid(row=0, column=1, sticky=W)
        self.TCPColor = StringVar(self.typeColorsFrame)
        self.TCPColor.set(self.typeColors["TCP"])
        self.TCPColorMenu = OptionMenu(self.typeColorsFrame, self.TCPColor, "None", "Red", "Green", "Blue", "Purple")
        self.TCPColorMenu.grid(row=1, column=1, sticky=W)
        # Selection of color for ICMP
        Label(self.typeColorsFrame, text="ICMP").grid(row=0, column=2, sticky=W)
        self.ICMPColor = StringVar(self.typeColorsFrame)
        self.ICMPColor.set(self.typeColors["ICMP"])
        self.ICMPColorMenu = OptionMenu(self.typeColorsFrame, self.ICMPColor, "None", "Red", "Green", "Blue", "Purple")
        self.ICMPColorMenu.grid(row=1, column=2, sticky=W)
        # Selection of color for UDP
        Label(self.typeColorsFrame, text="UDP").grid(row=0, column=3, sticky=W)
        self.UDPColor = StringVar(self.typeColorsFrame)
        self.UDPColor.set(self.typeColors["UDP"])
        self.UDPColorMenu = OptionMenu(self.typeColorsFrame, self.UDPColor, "None", "Red", "Green", "Blue", "Purple")
        self.UDPColorMenu.grid(row=1, column=3, sticky=W)


        # Selection of terminal type
        Label(self.rootFrame, text="Default Terminal:").grid(row=5, sticky=W)
        self.terminalVar = StringVar(self.rootFrame)
        self.terminalOption = OptionMenu(self.rootFrame, self.terminalVar, "xterm", "gterm")
        self.terminalOption.grid(row=5, column=1, sticky=W)
        terminalType = self.prefValues['terminalType']
        self.terminalVar.set(terminalType)

        # Field for CLI
        Label(self.rootFrame, text="Start CLI:").grid(row=6, sticky=W)
        self.cliStart = IntVar()
        self.cliButton = Checkbutton(self.rootFrame, variable=self.cliStart)
        self.cliButton.grid(row=6, column=1, sticky=W)
        if self.prefValues['startCLI'] == 0:
            self.cliButton.deselect()
        else:
            self.cliButton.select()

        # Field for showing IP Packets
        Label(self.rootFrame, text="Show IP address on packets:").grid(row=7, sticky=W)
        self.showAddrVar = StringVar(self.rootFrame)
        self.showaddrOption = OptionMenu(self.rootFrame, self.showAddrVar, "Source", "Destination", "None")
        self.showaddrOption.grid(row=7, column=1, sticky=W)
        self.showAddrVar.set(self.prefValues['showAddr'])

        # Field for showing nodeStats
        Label(self.rootFrame, text="Show Node Statistics Box:").grid(row=8, sticky=W)
        self.showNodeStats = IntVar()
        self.cshowNodeStats = Checkbutton(self.rootFrame, variable=self.showNodeStats)
        self.cshowNodeStats.grid(row=8, column=1, sticky=W)
        if self.prefValues['showNodeStats'] == 0:
            self.cshowNodeStats.deselect()
        else:
            self.cshowNodeStats.select()

        # Field for identifying packets belonging to same flow
        Label(self.rootFrame, text="Identify packets in the same flow and display in order:").grid(row=9, sticky=W)
        self.identifyFlows = IntVar()
        self.cidentifyFlows = Checkbutton(self.rootFrame, variable=self.identifyFlows)
        self.cidentifyFlows.grid(row=9, column=1, sticky=W)
        if self.prefValues['identifyFlows'] == 0:
            self.cidentifyFlows.deselect()
        else:
            self.cidentifyFlows.select()

    def apply(self):

        flowTime = FLOWTIME[self.flowTime.get()]
        self.typeColors['ARP'] = str(self.ARPColor.get())
        self.typeColors['TCP'] = str(self.TCPColor.get())
        self.typeColors['ICMP'] = str(self.ICMPColor.get())
        self.typeColors['UDP'] = str(self.UDPColor.get())
        typeColors = self.typeColors

        self.result = {'displayFlows': self.displayFlows.get(),
                       'displayHosts': self.displayHosts.get(),
                        'flowTime': flowTime,
                       'nodeColors': self.nodeColorsVar.get(),
                       'typeColors': typeColors,
                       'terminalType': self.terminalVar.get(),
                       'startCLI': self.cliStart.get(),
                       'showAddr': self.showAddrVar.get(),
                       'showNodeStats': self.showNodeStats.get(),
                       'identifyFlows': self.identifyFlows.get()
                       }

class FiltersDialog(tkSimpleDialog.Dialog):
    "Filters dialog"

    def __init__(self, parent, title, filterDefaults):

        self.filterValues = filterDefaults

        tkSimpleDialog.Dialog.__init__(self, parent, title)

    def body(self, master):
        "Create dialog body"
        self.rootFrame = master


        # Field for Show Packet Types
        Label(self.rootFrame, text="Show Packet Types:").grid(row=0, sticky=E)
        self.showPackets = Text(self.rootFrame, height = 1)
        self.showPackets.grid(row=0, column=1)
        showPackets =  self.filterValues['showPackets']
        for item in showPackets:
            self.showPackets.insert(END, item + ', ')

        # Field for Hide Packet Types
        Label(self.rootFrame, text="Hide Packet Types:").grid(row=2, sticky=E)
        self.hidePackets = Text(self.rootFrame, height = 1)
        self.hidePackets.grid(row=2, column=1)
        hidePackets =  self.filterValues['hidePackets']
        for item in hidePackets:
            self.hidePackets.insert(END, item + ', ')

        # Field for Hide Packets From IP or MAC
        Label(self.rootFrame, text="Hide Packets from IP or MAC:").grid(row=3, sticky=E)
        self.hideFromIPMAC = Text(self.rootFrame, height = 1)
        self.hideFromIPMAC.grid(row=3, column=1)
        hideFromIPMAC =  self.filterValues['hideFromIPMAC']
        for item in hideFromIPMAC:
            self.hideFromIPMAC.insert(END, item + ', ')

        # Field for Hide Packet To IP or MAC
        Label(self.rootFrame, text="Hide Packets To IP or MAC:").grid(row=4, sticky=E)
        self.hideToIPMAC = Text(self.rootFrame, height = 1)
        self.hideToIPMAC.grid(row=4, column=1)
        hideToIPMAC =  self.filterValues['hideToIPMAC']
        for item in hideToIPMAC:
            self.hideToIPMAC.insert(END, item + ', ')


        # initial focus
        return self.showPackets

    def apply(self):
        showPackets = str(self.showPackets.get("1.0",'end-1c')).replace(' ', '').replace('\n', '').replace('\r', '').split(',')
        hidePackets = str(self.hidePackets.get("1.0",'end-1c')).replace(' ', '').replace('\n', '').replace('\r', '').split(',')
        hideFromIPMAC = str(self.hideFromIPMAC.get("1.0",'end-1c')).replace(' ', '').replace('\n', '').replace('\r', '').split(',')
        hideToIPMAC = str(self.hideToIPMAC.get("1.0",'end-1c')).replace(' ', '').replace('\n', '').replace('\r', '').split(',')
        # Removing empty items from lists
        showPackets = filter(None, showPackets)
        hidePackets = filter(None, hidePackets)
        hideFromIPMAC = filter(None, hideFromIPMAC)
        hideToIPMAC = filter(None, hideToIPMAC)
        self.result= {
            'showPackets': showPackets,
            'hidePackets': hidePackets,
            'hideFromIPMAC': hideFromIPMAC,
            'hideToIPMAC': hideToIPMAC
        }


    @staticmethod
    def getOvsVersion():
        "Return OVS version"
        outp = quietRun("ovs-vsctl show")
        r = r'ovs_version: "(.*)"'
        m = re.search(r, outp)
        if m is None:
            print 'Version check failed'
            return None
        else:
            print 'Open vSwitch version is '+m.group(1)
            return m.group(1)

class NodeStats(object):

    def __init__(self, widget):
        self.widget = widget
        self.tipwindow = None
        self.id = None
        self.x = self.y = 0

    def showtip(self, text):
        "Display text in nodeStats window"
        self.text = text
        if self.tipwindow or not self.text:
            return
        x, y, _cx, cy = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 27
        y = y + cy + self.widget.winfo_rooty() +27
        self.tipwindow = tw = Toplevel(self.widget)
        tw.wm_overrideredirect(1)
        tw.wm_geometry("+%d+%d" % (x, y))
        try:
            tw.tk.call("::tk::unsupported::MacWindowStyle",
                       "style", tw._w,
                       "help", "noActivates")
        except TclError:
            pass
        label = Label(tw, text=self.text, justify=LEFT,
                      background="#ffffe0", relief=SOLID, borderwidth=1,
                      font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hidetip(self):
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()

class MiniNAM( Frame ):

    "A realtime network animator for Mininet."

    def __init__( self, parent=None, cheight=600, cwidth=1000 , net= None, locations={}):

        Frame.__init__( self, parent )
        self.action = None

        #Defaults for preferences and filters
        self.appPrefs={
            'displayFlows': 1,
            'displayHosts': 1,
            'flowTime': FLOWTIME[FLOWTIMEDEF],
            'nodeColors': 'Source',
            'typeColors': {'ARP': 'Red', 'TCP': 'Green', 'ICMP': 'Blue', 'UDP': 'Green'},
            'startCLI': 1,
            'terminalType': 'xterm',
            'showAddr': 'None',
            'showNodeStats': 0,
            'identifyFlows': 1
        }
        self.appFilters={
            'showPackets': ['TCP', 'UDP', 'ICMP'],    #ARP?
            'hidePackets': ['IPv6'],
            'hideFromIPMAC': ['0.0.0.0', '255.255.255.255'],
            'hideToIPMAC': ['0.0.0.0', '255.255.255.255']
        }

        # Style
        self.fixedFont = tkFont.Font ( family="DejaVu Sans Mono", size="14" )
        self.font = ( 'Geneva', 9 )
        self.smallFont = ( 'Geneva', 7 )
        self.bg = 'white'
        #If more hosts than this list then random colors are assigned to remaining hosts
        self.HOST_COLORS = ['#E57300', '#FF66B2', '#fa0004', '#b1b106', '#957aff', '#FF00FF', '#2f90d0', '#818c8d',
                       '#A93226', '#1b2ef8', '#3ef979', '#7c2ff9']
        self.Controller_Color = '#9D9D9D'
        self.images = miniImages()

        # Title
        self.appName = 'MiniNAM'
        self.top = self.winfo_toplevel()
        self.top.title( self.appName )

        # Menu bar
        self.createMenubar()

        # Editing canvas
        self.cheight, self.cwidth = cheight, cwidth
        self.cframe, self.canvas = self.createCanvas()

        # Layout
        self.cframe.grid( column=1, row=0 )
        self.columnconfigure( 1, weight=1 )
        self.rowconfigure( 0, weight=1 )
        self.pack( expand=True, fill='both' )

        # Info boxes
        self.aboutBox = None
        self.infoBox = None

        # Initialize node data
        self.nodeBindings = self.createNodeBindings()
        self.nodePrefixes = { 'LegacyRouter': 'r', 'LegacySwitch': 's', 'Switch': 's', 'Host': 'h' , 'Controller': 'c'}
        self.widgetToItem = {}
        self.itemToWidget = {}
        self.Nodes = []
        # intfdata is [{"node":"-1", 'color': None, "type":"-1", "interface": "-1", "mac":"-1", "ip": "-1", "dgw":"-1", "link": "-1", "TXP":0, "RXP":0, "TXB":0, "RXB":0}]
        self.intfData = []

        # Initialize link tool
        self.link = self.linkWidget = None

        # Selection support
        self.selection = None

        # Keyboard and Popup bindings
        self.bind( '<Control-q>', lambda event: self.quit() )
        self.focus()
        self.canvas.bind('<Button-1>', self.setFocus)
        self.hostPopup = Menu(self.top, tearoff=0, takefocus=1)
        self.hostPopup.add_command(label='Host Options', font=self.font)
        self.hostPopup.add_separator()
        self.hostPopup.add_command(label='Terminal', font=self.font, command=self.xterm )
        self.hostPopup.bind("<FocusOut>", self.popupFocusOut)

        self.legacyRouterPopup = Menu(self.top, tearoff=0, takefocus=1)
        self.legacyRouterPopup.add_command(label='Router Options', font=self.font)
        self.legacyRouterPopup.add_separator()
        self.legacyRouterPopup.add_command(label='Terminal', font=self.font, command=self.xterm )
        self.legacyRouterPopup.bind("<FocusOut>", self.popupFocusOut)

        self.switchPopup = Menu(self.top, tearoff=0, takefocus=1)
        self.switchPopup.add_command(label='Switch Options', font=self.font)
        self.switchPopup.add_separator()
        self.switchPopup.add_command(label='List bridge details', font=self.font, command=self.listBridge )
        self.switchPopup.bind("<FocusOut>", self.popupFocusOut)

        self.linkPopup = Menu(self.top, tearoff=0, takefocus=1)
        self.linkPopup.add_command(label='Link Options', font=self.font)
        self.linkPopup.add_separator()
        self.linkPopup.add_command(label='Link Up', font=self.font, command=self.linkUp )
        self.linkPopup.add_command(label='Link Down', font=self.font, command=self.linkDown )
        self.linkPopup.bind("<FocusOut>", self.popupFocusOut)


        # Event handling initalization
        self.linkx = self.linky = self.linkItem = None
        self.lastSelection = None

        # Model initialization
        self.packetImage = []
        self.flowQueues = {}
        self.PLACEMENT = {'block': SwitchBinPlacer, 'random': RandomPlacer}
        self.links = {}
        self.cli = None

        #Setting up values when MiniNAM class is called from a script
        self.nodelocations = locations
        self.options = None
        self.args = None
        self.validate = None
        self.net = net
        self.active = True

        #Setup network if MiniNAM is called from CLI
        if self.net is None:
            self.parseArgs()
            self.setup()
            self.begin()
            if self.options.test == 'cli':
                self.startCLI()

        #Exit if network wasn't created properly
        if self.net is None:
            error('Network does not exist. Do not use net(stop) in your script if you want GUI to load.')
            sys.exit()

        #Start siniffing packets on Mininet interfaces
        self.sniff = Thread( target=self.sniff )
        self.sniff.daemon = True
        self.sniff.start()

        #Start CLI thread if requested
        if self.appPrefs['startCLI'] == 1:
            self.startCLI()

        #Gather topology info and create nodes
        self.TopoInfo()
        self.createNodes()

        # Place window at bottom
        self.top.geometry("%dx%d%+d%+d" % (self.cwidth, self.cheight, 1, 1000))

        # Close window gracefully
        Wm.wm_protocol( self.top, name='WM_DELETE_WINDOW', func=self.quit )

        #Set the logo for MiniNAM
        logo = self.images['Logo']
        self.top.tk.call('wm', 'iconphoto', self.top._w, logo)

    # Arguments and Network

    def custom( self, _option, _opt_str, value, _parser ):
        "Parse custom file and add params."
        files = []
        if os.path.isfile( value ):
            # Accept any single file (including those with commas)
            files.append( value )
        else:
            # Accept a comma-separated list of filenames
            files += value.split(',')

        for fileName in files:
            customs = {}
            if os.path.isfile( fileName ):
                execfile( fileName, customs, customs )
                for name, val in customs.iteritems():
                    self.setCustom( name, val )
            else:
                raise Exception( 'could not find custom file: %s' % fileName )

    def setCustom( self, name, value ):
        "Set custom parameters for Mininet."
        if name.upper() == 'NET':
            info('*** Loading network from custom file ***\n')
            self.net = value
        elif name in ( 'topos', 'switches', 'hosts', 'controllers' ):
            # Update dictionaries
            param = name.upper()
            try:
                globals()[ param ].update( value )
                globals()[str(param + '_TYPES')].append( value.keys()[0])
            except:
                pass
        elif name == 'validate':
            # Add custom validate function
            self.validate = value

        elif name == 'locations':
            self.nodelocations = value

        else:
            # Add or modify global variable or class
            globals()[ name ] = value

    def configs( self, _option, _opt_str, value, _parser ):

        "Load custom configs."
        fileName = value

        if not os.path.isfile(fileName):
            print 'Could not find config file: %s. Loading default preferences and filters.' % fileName
            return
        f = open(fileName, 'r')
        loadedPrefs = self.convertJsonUnicode(json.load(f))
        # Load application preferences
        if 'preferences' in loadedPrefs:
            self.appPrefs = dict(self.appPrefs.items() + loadedPrefs['preferences'].items())
        # Load application filters
        if 'filters' in loadedPrefs:
            self.appFilters = dict(self.appFilters.items() + loadedPrefs['filters'].items())
        f.close()

    def setNat( self, _option, opt_str, value, parser ):
        "Set NAT option(s)"
        assert self  # satisfy pylint
        parser.values.nat = True
        # first arg, first char != '-'
        if parser.rargs and parser.rargs[ 0 ][ 0 ] != '-':
            value = parser.rargs.pop( 0 )
            _, args, kwargs = splitArgs( opt_str + ',' + value )
            parser.values.nat_args = args
            parser.values.nat_kwargs = kwargs
        else:
            parser.values.nat_args = []
            parser.values.nat_kwargs = {}

    def addDictOption(self, opts, choicesDict, default, name, **kwargs):
        """Convenience function to add choices dicts to OptionParser.
           opts: OptionParser instance
           choicesDict: dictionary of valid choices, must include default
           default: default choice key
           name: long option name
           kwargs: additional arguments to add_option"""
        helpStr = ('|'.join(sorted(choicesDict.keys())) +
                   '[,param=value...]')
        helpList = ['%s=%s' % (k, v.__name__)
                    for k, v in choicesDict.items()]
        helpStr += ' ' + (' '.join(helpList))
        params = dict(type='string', default=default, help=helpStr)
        params.update(**kwargs)
        opts.add_option('--' + name, **params)

    def parseArgs( self ):
        """Parse command-line args and return options object.
           returns: opts parse options dict"""

        desc = ( "The %prog utility creates Mininet network from the\n"
                 "command line, loads a GUI with the created topology and\n"
                 "displays any network traffic generated." )

        usage = ( '%prog [options]\n'
                  '(type %prog -h for details)' )

        opts = OptionParser( description=desc, usage=usage )
        opts.add_option('--config', action='callback',
                        callback=self.configs,
                        type='string',
                        help='load custom preferences from .config file'
                        )
        opts.add_option('--custom', action='callback',
                        callback=self.custom,
                        type='string',
                        help='read custom classes, params or network (with net as name) from .py file(s)'
                        )

        self.addDictOption( opts, SWITCHES, SWITCHDEF, 'switch' )
        self.addDictOption( opts, HOSTS, HOSTDEF, 'host' )
        self.addDictOption( opts, CONTROLLERS, [], 'controller', action='append' )
        self.addDictOption( opts, LINKS, LINKDEF, 'link' )
        self.addDictOption( opts, TOPOS, TOPODEF, 'topo' )

        opts.add_option( '--clean', '-c', action='store_true',
                         default=False, help='clean and exit' )

        # optional tests to run
        TESTS = ['cli', 'build', 'pingall', 'pingpair', 'iperf', 'all', 'iperfudp', 'none']

        opts.add_option( '--test', type='choice', choices=TESTS,
                         default=TESTS[ -1 ],
                         help='|'.join( TESTS ) )
        opts.add_option( '--xterms', '-x', action='store_true',
                         default=False, help='spawn xterms for each node' )
        opts.add_option( '--ipbase', '-i', type='string', default='10.0.0.0/8',
                         help='base IP address for hosts' )
        opts.add_option( '--mac', action='store_true',
                         default=False, help='automatically set host MACs' )
        opts.add_option( '--arp', action='store_true',
                         default=False, help='set all-pairs ARP entries' )
        opts.add_option( '--verbosity', '-v', type='choice',
                         choices=LEVELS.keys(), default = 'info',
                         help = '|'.join( LEVELS.keys() )  )
        opts.add_option( '--innamespace', action='store_true',
                         default=False, help='sw and ctrl in namespace?' )
        opts.add_option( '--listenport', type='int', default=6634,
                         help='base port for passive switch listening' )
        opts.add_option( '--nolistenport', action='store_true',
                         default=False, help="don't use passive listening " +
                         "port")
        opts.add_option( '--pre', type='string', default=None,
                         help='CLI script to run before tests' )
        opts.add_option( '--post', type='string', default=None,
                         help='CLI script to run after tests' )
        opts.add_option( '--pin', action='store_true',
                         default=False, help="pin hosts to CPU cores "
                         "(requires --host cfs or --host rt)" )
        opts.add_option( '--nat', action='callback', callback=self.setNat,
                         help="adds a NAT to the topology that"
                         " connects Mininet hosts to the physical network."
                         " Warning: This may route any traffic on the machine"
                         " that uses Mininet's"
                         " IP subnet into the Mininet network."
                         " If you need to change"
                         " Mininet's IP subnet, see the --ipbase option." )
        opts.add_option( '--version', action='callback', callback=version,
                         help='prints the version and exits' )
        opts.add_option( '--cluster', type='string', default=None,
                         metavar='server1,server2...',
                         help=( 'run on multiple servers (experimental!)' ) )
        opts.add_option( '--placement', type='choice',
                         choices=self.PLACEMENT.keys(), default='block',
                         metavar='block|random',
                         help=( 'node placement for --cluster '
                                '(experimental!) ' ) )

        self.options, self.args = opts.parse_args()

        # We don't accept extra arguments after the options
        if self.args:
            opts.print_help()
            sys.exit()

    def setup( self ):
        "Setup and validate environment."
        lg.setLogLevel( self.options.verbosity )

    def begin( self ):
        "Create and run mininet."

        if self.options.cluster:
            servers = self.options.cluster.split( ',' )
            for server in servers:
                ClusterCleanup.add( server )

        if self.options.clean:
            cleanup()
            sys.exit()

        if not self.options.controller:
            # Update default based on available controllers
            CONTROLLERS[ 'default' ] = findController()
            self.options.controller = [ 'default' ]
            if not CONTROLLERS[ 'default' ]:
                self.options.controller = [ 'none' ]
                if self.options.switch == 'default':
                    info( '*** No default OpenFlow controller found '
                          'for default switch!\n' )
                    info( '*** Falling back to OVS Bridge\n' )
                    self.options.switch = 'ovsbr'
                elif self.options.switch not in ( 'ovsbr', 'lxbr' ):
                    raise Exception( "Could not find a default controller "
                                     "for switch %s" %
                                     self.options.switch )

        topo = buildTopo( TOPOS, self.options.topo )
        switch = customClass( SWITCHES, self.options.switch )
        host = customClass( HOSTS, self.options.host )
        controller = [ customClass( CONTROLLERS, c )
                       for c in self.options.controller ]

        if self.options.switch == 'user' and self.options.link == 'default':
            # Using TCULink with UserSwitch
            # Use link configured correctly for UserSwitch
            self.options.link = 'tcu'

        link = customClass( LINKS, self.options.link )

        if self.validate:
            self.validate( self.options )

        ipBase = self.options.ipbase
        xterms = self.options.xterms
        mac = self.options.mac
        arp = self.options.arp
        pin = self.options.pin
        listenPort = None
        if not self.options.nolistenport:
            listenPort = self.options.listenport

        # Handle inNamespace, cluster options
        inNamespace = self.options.innamespace
        cluster = self.options.cluster
        if inNamespace and cluster:
            print "Please specify --innamespace OR --cluster"
            sys.exit()
        Net = MininetWithControlNet if inNamespace else Mininet
        if cluster:
            warn( '*** WARNING: Experimental cluster mode!\n'
                  '*** Using RemoteHost, RemoteOVSSwitch, RemoteLink\n' )
            host, switch, link = RemoteHost, RemoteOVSSwitch, RemoteLink
            Net = partial( MininetCluster, servers=servers,
                           placement=self.PLACEMENT[ self.options.placement ] )


        self.net = Net( topo=topo,
                  switch=switch, host=host, controller=controller,
                  link=link,
                  ipBase=ipBase,
                  inNamespace=inNamespace,
                  xterms=xterms, autoSetMacs=mac,
                  autoStaticArp=arp, autoPinCpus=pin,
                  listenPort=listenPort )

        if self.options.ensure_value( 'nat', False ):
            nat = self.net.addNAT( *self.options.nat_args,
                             **self.options.nat_kwargs )
            nat.configDefault()

        self.net.start()

    def runTest( self ):

        cluster = self.options.cluster
        cli = ClusterCLI if cluster else CLI
        if self.options.pre:
            cli(self.net, script=self.options.pre)
        test = self.options.test
        ALTSPELLING = {'pingall': 'pingAll',
                       'pingpair': 'pingPair',
                       'iperfudp': 'iperfUdp',
                       'iperfUDP': 'iperfUdp'}

        test = ALTSPELLING.get(test, test)

        if test == 'none':
            pass
        elif test == 'all':
            self.net.waitConnected()
            self.net.start()
            self.net.ping()
            self.net.iperf()
        elif test == 'cli':
            cli( self.net )
            pass
        elif test != 'build':
            self.net.waitConnected()
            getattr(self.net, test)()

        if self.options.post:
            cli(self.net, script=self.options.post)

    # Topology and Sniffing

    def TopoInfo(self):

        #Gather node info for all nodes in the network
        for item , value in self.net.items():
            if value.__class__.__name__ in CONTROLLERS_TYPES:
                self.Nodes.append({'name': item, 'widget':None, 'type':value.__class__.__name__, 'ip':value.ip, 'port':value.port, 'color':self.Controller_Color})
            elif value.__class__.__name__ in SWITCHES_TYPES:
                self.Nodes.append({'name': item, 'widget': None, 'type': value.__class__.__name__, 'dpid':value.dpid, 'color': None, 'controllers':[]})
            elif value.__class__.__name__ in HOSTS_TYPES:
                if  self.appPrefs['displayHosts'] == 1:
                    self.Nodes.append({'name': item, 'widget': None, 'type': value.__class__.__name__, 'ip':value.IP(), 'color': None})
                else:
                    continue
            else:
                self.Nodes.append(
                    {'name': item, 'widget': None, 'type': value.__class__.__name__, 'color': None})

            #Gather interface info for all interfaces of a node
            for intf in value.intfList():
                intf2 = str(intf.link).replace(intf.name,'').replace('<->','')
                if intf2 != 'None':
                    self.intfData.append({'node': item, 'type': value.__class__.__name__, 'interface': intf.name, 'mac': intf.mac, 'ip':intf.ip,
                                  'link': intf2, 'TXP': 0, 'RXP': 0, 'TXB': 0, 'RXB': 0})

        #To find and save the controller that each switch is connected to. Needed because there can be more than one controller.
        for switch in self.Nodes:
            if switch['type'] in SWITCHES_TYPES:
                try:
                    switch_info = check_output(["ovs-vsctl", "get-controller", switch['name']])
                except:
                    switch_info = '-1'
                first_controller = None
                for controller in self.Nodes:
                    if controller['type'] in CONTROLLERS_TYPES:
                        controller_info = str(controller['ip']) + ':' + str(controller['port'])
                        if controller_info in switch_info:
                            switch['controllers'].append(controller['name'])
                        if first_controller == None:
                            first_controller = controller['name']
                # TODO: Assign user switch properly to the correct controller
                # Currently just assigning the first controller to the switch. Will work if there is only one controller.
                if switch['controllers'] == []:
                    switch['controllers'].append(first_controller)


    def intfExists(self, interface):
        for data in self.intfData:
            if data["interface"] == interface:
                return data
        return None

    def sniff( self ):

        #Create raw socket to receive everything
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        except socket.error as msg:
            print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
            sys.exit()
        # receive a packet
        while True:
            if self.appPrefs['displayFlows'] == 0:
                continue

            packet = s.recvfrom(65565)

            interface = packet[1][0]
            direction = "incoming"
            if packet[1][2] == socket.PACKET_OUTGOING:
                direction = "outgoing"

            # packet string from tuple
            packet = packet[0]

            #Parse the packet and get info in headers
            PacketInfo = packetParser(packet)

            eth_protocol = PacketInfo['eth_protocol']
            srcMAC, dstMAC = PacketInfo['srcMAC'], PacketInfo['dstMAC']
            ip_protocol = PacketInfo['ip_protocol']
            s_addr, d_addr = PacketInfo['s_addr'], PacketInfo['d_addr']
            data = PacketInfo['data']

            # TODO: Sniff the controller packets

            try:
                #Skip packet if it is supposed to be filtered
                if self.filterPacket(srcMAC, dstMAC, s_addr, d_addr, eth_protocol, ip_protocol):
                    continue
            except:
                continue

            try:
                #Make sure that the interface info exists in our topology
                intf = self.intfExists(interface)
                if not intf:
                    continue
            except Exception:
                continue

            PacketInfo['interface'] = interface
            PacketInfo['direction'] = direction

            try:
                #MiniNAM sniffs packets as they are received, except for the packets going to the host.
                #This is because hosts are separate processes in Mininet and their interfaces are not
                #actual interfaces on the machine. So to sniff packets reaching hosts, we look at the
                #packets leaving the last-hop switch.
                if direction == "outgoing":
                    intf["TXB"] += len(packet)
                    intf["TXP"] += 1
                    link = self.intfExists(intf["link"])
                    if link['type'] in HOSTS_TYPES or link['type'] in ['LinuxRouter', 'LinuxSwitch'] :
                        link["RXB"] += len(packet)
                        link["RXP"] += 1
                        #Check if the packet should be color coded by IP
                        if self.appPrefs['nodeColors'] == 'Source':
                            sender = next((node for node in self.Nodes if 'ip' in node if node['ip'] == s_addr), None)
                            PacketInfo['node_color'] = sender['color'] if sender else 'black'
                        if self.appPrefs['nodeColors'] == 'Destination':
                            receiver = next((node for node in self.Nodes if 'ip' in node if node['ip'] == d_addr), None)
                            PacketInfo['node_color'] = receiver['color'] if receiver else 'black'
                        src, dst = intf["node"], intf["link"].split('-')[0]
                        #To view the effect of link delays LinkTime value can be replaced by actual link delays set in Mininet
                        PacketInfo['time'] = LinkTime
                        #Create a packet object to be displayed in the GUI
                        self.createPacket(src, dst, PacketInfo)

                #Sniff packets reaching at any interface
                if direction == "incoming":
                    intf["RXB"] += len(packet)
                    intf["RXP"] += 1
                    link = self.intfExists(intf["link"])
                    if link['type'] in HOSTS_TYPES or link['type'] in ['LinuxRouter', 'LinuxSwitch']:
                        link = self.intfExists(intf["link"])
                        link["TXB"] += len(packet)
                        link["TXP"] += 1
                    # Check if the packet should be color coded by IP
                    if self.appPrefs['nodeColors'] == 'Source':
                        sender = next((node for node in self.Nodes if 'ip' in node if node['ip'] == s_addr), None)
                        PacketInfo['node_color'] = sender['color'] if sender else 'black'
                    if self.appPrefs['nodeColors'] == 'Destination':
                        receiver = next((node for node in self.Nodes if 'ip' in node if node['ip'] == d_addr), None)
                        PacketInfo['node_color'] = receiver['color'] if receiver else 'black'
                    src, dst = intf["link"].split('-')[0], intf["node"]
                    # To view the effect of link delays LinkTime value can be replaced by actual link delays set in Mininet
                    PacketInfo['time'] = LinkTime
                    # Create a packet object to be displayed in the GUI
                    self.createPacket(src, dst, PacketInfo)

            except Exception:
                pass

    def createNodes(self):
        #Drawing node Widgets
        for node in self.Nodes:
            if not self.findWidgetByName(node['name']):
                location = self.nodelocations[node['name']] if node['name'] in self.nodelocations else (random.randrange(70,self.cwidth-100), random.randrange(70,self.cheight-100))
                self.newNamedNode(node, location[0], location[1])

        #Drawing data links
        for data in self.intfData:
            try:
                self.drawLink(data["interface"].split('-')[0], data["link"].split('-')[0])
            except:
                pass

        #Drawing control links
        for switch in self.Nodes:
            try:
                for ctrlr in switch['controllers']:
                    self.drawLink(ctrlr, switch['name'])
            except:
                pass

    def filterPacket(self, srcMAC, dstMAC, s_addr, d_addr, eth_protocol, ip_protocol):
        try:
            if s_addr is not None:
                if s_addr in self.appFilters['hideFromIPMAC']:
                    return True
            if d_addr is not None:
                if d_addr in self.appFilters['hideToIPMAC']:
                    return True
            if srcMAC is not None:
                if srcMAC in self.appFilters['hideFromIPMAC']:
                    return True
            if dstMAC is not None:
                if dstMAC in self.appFilters['hideToIPMAC']:
                    return True
            if ip_protocol is not None:
                if IP_Protocols[str(ip_protocol)] in self.appFilters['hidePackets']:
                    return True
            if eth_protocol is not None:
                if Eth_Protocols[str(eth_protocol)] in self.appFilters['hidePackets']:
                    return True
            if 'ALL' in [t.upper() for t in self.appFilters['showPackets']]:
                return False
            if ip_protocol is not None:
                if IP_Protocols[str(ip_protocol)] in self.appFilters['showPackets']:
                    return False
            if eth_protocol is not None:
                if Eth_Protocols[str(eth_protocol)] in self.appFilters['showPackets']:
                    return False
            return True
        except:
            return True

    def createPacket(self, src, dst, PacketInfo):
        try:
            #Get the queue in which the packet should be added
            q = self.getQueue(PacketInfo)
            if q is not None:
                #Refresh a queue if it grows above 100 packets
                if q.qsize() > 100:
                    self.clearQueue(q)
                #Create a thread to display packet and add it to the queue
                thr = Thread(target= self.displayPacket, args=(src, dst, PacketInfo))
                thr.daemon = True
                q.put(thr)
        except Exception as e:
            print e

    def displayPacket(self, src, dst, PacketInfo):

        try:
            c = self.canvas
            s = self.findWidgetByName(src)
            d = self.findWidgetByName(dst)
            srcx, srcy = c.coords(self.widgetToItem[s])
            dstx, dsty = c.coords(self.widgetToItem[d])

            #Draw a rectangle shape for the packet
            image1 = Image.new("RGBA", (30, 15))
            draw = ImageDraw.Draw(image1)
            draw.polygon([(0, 0), (0, 15), (30, 15), (30, 0)], "black")

            #Color code packet based on IP if needed
            try:
                node_color = PacketInfo["node_color"]
            except:
                node_color = 'black'
            draw.polygon([(10, 0), (10, 15), (30, 15), (30, 0)], node_color)

            # Color code packet by type
            try:
                eth_color = self.appPrefs['typeColors'][Eth_Protocols[PacketInfo['eth_protocol']]]
                if eth_color == 'None': eth_color = 'black'
            except:
                eth_color = None
            try:
                ip_color = self.appPrefs['typeColors'][IP_Protocols[PacketInfo["ip_protocol"]]]
                if ip_color == 'None':  ip_color = 'black'
            except:
                ip_color = None

            if eth_color is not None:
                draw.polygon([(0, 0), (0, 15), (10, 15), (10, 0)], eth_color)
            if ip_color is not None:
                draw.polygon([(0, 0), (0, 15), (10, 15), (10, 0)], ip_color)

            #If IP address is not displayed then rotate the packet along the link
            if self.appPrefs['showAddr'] == 'None':
                angle = -1 * atan2(dsty-srcy,dstx-srcx)
                dx = 7 * sin(angle)
                dy = 7 * cos(angle)
                angle = 180*angle/pi
                packetImage = itk.PhotoImage(image1.rotate(angle, expand=True))

            else:
                if self.appPrefs['showAddr'] == 'Source':
                    addr = PacketInfo['s_addr']
                elif self.appPrefs['showAddr'] == 'Destination':
                    addr = PacketInfo['d_addr']

                address = addr.split('.')[0] + '.' + addr.split('.')[-1]
                draw.text((0, 0), address)
                packetImage = itk.PhotoImage(image1)
                dx, dy = 0, 0

            self.packetImage.append(packetImage)
            packet = c.create_image(srcx+dx, srcy+dy, image=packetImage)
            deltax = (dstx - srcx) / 50
            deltay = (dsty - srcy) / 50
            delta = deltax, deltay

            t = float(self.appPrefs['flowTime']) * float(PacketInfo['time']) / 50000  # 1000 for ms and 50 for steps
            self.movePacket(packet, packetImage, delta, t)

        except Exception:
            pass

    def movePacket(self, packet, image, delta, t):
        c = self.canvas
        i = 0
        #Move the packet in 50 steps then remove the image
        while i < 50:
            if self.active:
                i+=1
                c.move(packet, delta[0], delta[1])
                c.update()
                time.sleep(t)
        c.delete(packet)
        self.packetImage.remove(image)

    def getQueue(self, PacketInfo):
        eth_protocol, ip_protocol = PacketInfo['eth_protocol'], PacketInfo['ip_protocol']
        s_addr, d_addr = PacketInfo['s_addr'], PacketInfo['d_addr']
        interface = PacketInfo['interface']
        #USE THE FOLLOWING FOR NAT
        #For dynamically detecting NAT addresses, NAT details can be detected from PacketInfo
        try:
            if s_addr == '10.0.0.1': s_addr = '192.168.1.100'
            if d_addr == '10.0.0.1': d_addr = '192.168.1.100'
        except Exception as e:
            pass

        addr1, addr2 = s_addr, d_addr

        t = float(self.appPrefs['flowTime']) * float(PacketInfo['time']) / 50000   #sec to ms 1000 and 50 steps

        #Separate queue for each interface for real-time or if not trying to identify flows
        if self.appPrefs['flowTime'] == 1 or self.appPrefs['identifyFlows'] == 0:
            q_name = ip_protocol + addr1 + addr2 + interface
            if q_name in self.flowQueues:
                return self.flowQueues[q_name]
            else:
                self.flowQueues[q_name] = Queue.Queue()
                qt = Thread(target=self.startQueue, args=(self.flowQueues[q_name], t))
                qt.daemon = True
                qt.start()
                return self.flowQueues[q_name]

        #Queues based on packet type, s_addr and d_addr
        else:
            q_name1 = ip_protocol+addr1+addr2
            q_name2 = ip_protocol+addr2+addr1
            if q_name1 in self.flowQueues:
                return self.flowQueues[q_name1]
            elif q_name2 in self.flowQueues:
                return self.flowQueues[q_name2]
            else:
                self.flowQueues[q_name1] =  Queue.Queue()
                qt = Thread(target=self.startQueue, args=(self.flowQueues[q_name1],t))
                qt.daemon = True
                qt.start()
                return self.flowQueues[q_name1]

    def startQueue(self, q, t):
        while True:
            thr = q.get()
            # For realtime display, empty queue more frequently to display up-to-date packets
            if self.appPrefs['flowTime'] == 1:
                while not q.empty():
                    q.task_done()
                    thr = q.get()
            thr.start()

            while thr.isAlive():
                time.sleep(t)
                pass
            try:
                q.task_done()
            except:
                pass

    def clearQueue( self, qu=None):
        "To clear queue and remove all enqueued packets"
        if qu is None:
            for q in self.flowQueues:
                while not self.flowQueues[q].empty():
                    self.flowQueues[q].task_done()
                    self.flowQueues[q].get()
        else:
            while not qu.empty():
                qu.task_done()
                qu.get()

    # Canvas

    def createCanvas( self ):
        "Create and return our scrolling canvas frame."
        f = Frame( self )

        canvas = Canvas( f, width=self.cwidth, height=self.cheight,
                         bg=self.bg )

        # Scroll bars
        xbar = Scrollbar( f, orient='horizontal', command=canvas.xview )
        ybar = Scrollbar( f, orient='vertical', command=canvas.yview )
        canvas.configure( xscrollcommand=xbar.set, yscrollcommand=ybar.set )

        # Resize box
        resize = Label( f, bg='white' )

        # Layout
        canvas.grid( row=0, column=1, sticky='nsew')
        ybar.grid( row=0, column=2, sticky='ns')
        xbar.grid( row=1, column=1, sticky='ew' )
        resize.grid( row=1, column=2, sticky='nsew' )


        # Resize behavior
        f.rowconfigure( 0, weight=1 )
        f.columnconfigure( 1, weight=1 )
        f.grid( row=0, column=0, sticky='nsew' )
        f.bind( '<Configure>', lambda event: self.updateScrollRegion() )

        return f, canvas

    def updateScrollRegion( self ):
        "Update canvas scroll region to hold everything."
        bbox = self.canvas.bbox( 'all' )
        if bbox is not None:
            self.canvas.configure( scrollregion=( 0, 0, bbox[ 2 ],
                                   bbox[ 3 ] ) )

    def canvasx( self, x_root ):
        "Convert root x coordinate to canvas coordinate."
        c = self.canvas
        return c.canvasx( x_root ) - c.winfo_rootx()

    def canvasy( self, y_root ):
        "Convert root y coordinate to canvas coordinate."
        c = self.canvas
        return c.canvasy( y_root ) - c.winfo_rooty()

    def popupFocusOut(self, event=None):
        event.widget.unpost()

    def setFocus(self, event=None):
        event.widget.focus_set()

    # Generic node handlers

    def findWidgetByName( self, name ):
        for widget in self.widgetToItem:
            if name ==  widget[ 'text' ]:
                return widget

    def findItem( self, x, y ):
        "Find items at a location in our canvas."
        items = self.canvas.find_overlapping( x, y, x, y )
        if len( items ) == 0:
            return None
        else:
            return items[ 0 ]

    def nodeIcon( self, node, name , color):
        "Create a new node icon."
        icon = Button( self.canvas, image=self.images[ node ],
                       text=name, compound='top' )
        icon.config(highlightbackground=color, highlightcolor=color, highlightthickness=3)
        # Unfortunately bindtags wants a tuple
        bindtags = [ str( self.nodeBindings ) ]
        bindtags += list( icon.bindtags() )
        icon.bindtags( tuple( bindtags ) )
        return icon

    def randColor(self):

        i =0;
        color = self.HOST_COLORS[i]
        try:
            while color in [node['color'] for node in self.Nodes]:
                i+=1
                color = self.HOST_COLORS[i]
        except:
            color = "#" + ("%06x" % random.randint(0, 16777215))
            while any(color in sublist for sublist in self.Nodes):
                color = "#" + ("%06x" % random.randint(0, 16777215))

        return color

    def newNamedNode(self, Node, x, y):
        name = Node['name']
        type = Node['type']
        color = None
        #Add a new node to our canvas.
        c = self.canvas

        if type in LEGACY_TYPES:
            if 'ROUTER' in type.upper():
                node = 'LegacyRouter'
            else:
                node = 'LegacySwitch'

        elif type in SWITCHES_TYPES:
            node = 'Switch'

        elif type in HOSTS_TYPES:
            node = 'Host'
            color = self.randColor()
        elif type in CONTROLLERS_TYPES:
            node = 'Controller'
            color = self.Controller_Color
        else:
            print "Specify node type for ", Node['name']


        icon = self.nodeIcon(node, name, color)
        item = self.canvas.create_window(x, y, anchor='c', window=icon,
                                         tags=node)
        self.widgetToItem[icon] = item
        self.itemToWidget[item] = icon
        self.selectItem(item)
        icon.links = {}

        Node['color'] , Node['widget'] = color, item

        self.showNodeStats(icon)
        icon.bind('<Button-1>', self.setFocus)
        if 'Switch' == node:
            icon.bind('<Button-3>', self.do_switchPopup)
        if 'LegacyRouter' == node:
            icon.bind('<Button-3>', self.do_legacyRouterPopup)
        if 'LegacySwitch' == node:
            icon.bind('<Button-3>', self.do_legacySwitchPopup)
        if 'Host' == node:
            icon.bind('<Button-3>', self.do_hostPopup)
        if 'Controller' == node:
            icon.bind('<Button-3>', self.do_controllerPopup)
        self.updateScrollRegion()

    def createNodeBindings( self ):
        "Create a set of bindings for nodes."
        bindings = {
            '<ButtonPress-1>': self.selectNode,
            '<B1-Motion>': self.dragNodeAround,
            '<Enter>': self.enterNode,
            '<Leave>': self.leaveNode
        }
        l = Label()  # lightweight-ish owner for bindings
        for event, binding in bindings.items():
            l.bind( event, binding )
        return l

    def selectItem( self, item ):
        "Select an item and remember old selection."
        self.lastSelection = self.selection
        self.selection = item

    def enterNode( self, event ):
        "Select node on entry."
        self.selectNode( event )

    def leaveNode( self, _event ):
        "Restore old selection on exit."
        self.selectItem( self.lastSelection )

    def showNodeStats(self, widget):
        nodeStats = NodeStats(widget)
        def enter(_event):
            if self.appPrefs['showNodeStats'] == 0:
                return

            TXP = 0; TXB = 0; RXP = 0; RXB = 0
            node = widget[ 'text' ]
            for data in self.intfData:
                if data['node'] == node:
                    TXP += data['TXP'];TXB+=data['TXB']; RXP+=data['RXP']; RXB+=data['RXB'];
            text = "TXP: " + str(TXP) + "\n" + "RXP: " + str(RXP) + "\n" + "TXB: " + str(TXB) + "\n" + "RXB: " + str(RXB)
            nodeStats.showtip(text)
        def leave(_event):
            nodeStats.hidetip()
        widget.bind('<Enter>', enter)
        widget.bind('<Leave>', leave)

    # Specific node handlers

    def selectNode( self, event ):
        "Select the node that was clicked on."
        item = self.widgetToItem.get( event.widget, None )
        self.selectItem( item )

    def dragNodeAround( self, event ):
        "Drag a node around on the canvas."
        c = self.canvas
        # Convert global to local coordinates;
        # Necessary since x, y are widget-relative
        x = self.canvasx( event.x_root )
        y = self.canvasy( event.y_root )
        w = event.widget
        # Adjust node position
        item = self.widgetToItem[ w ]
        c.coords( item, x, y )
        # Adjust link positions
        for dest in w.links:
            link = w.links[ dest ]
            item = self.widgetToItem[ dest ]
            x1, y1 = c.coords( item )
            c.coords( link, x, y, x1, y1 )
        self.updateScrollRegion()

    def createControlLinkBindings( self ):
        "Create a set of bindings for nodes."
        # Link bindings
        # Selection still needs a bit of work overall
        # Callbacks ignore event

        def select( _event, link=self.link ):
            "Select item on mouse entry."
            self.selectItem( link )

        def highlight( _event, link=self.link ):
            "Highlight item on mouse entry."
            self.selectItem( link )
            self.canvas.itemconfig( link, fill='green' )

        def unhighlight( _event, link=self.link ):
            "Unhighlight item on mouse exit."
            self.canvas.itemconfig( link, fill='red' )

        self.canvas.tag_bind( self.link, '<Enter>', highlight )
        self.canvas.tag_bind( self.link, '<Leave>', unhighlight )
        self.canvas.tag_bind( self.link, '<ButtonPress-1>', select )

    def createDataLinkBindings( self ):
        "Create a set of bindings for nodes."
        # Link bindings
        # Selection still needs a bit of work overall
        # Callbacks ignore event

        def select( _event, link=self.link ):
            "Select item on mouse entry."
            self.selectItem( link )
            self.canvas.focus_set()


        def highlight( _event, link=self.link ):
            "Highlight item on mouse entry."
            self.selectItem( link )
            self.canvas.itemconfig( link, fill='green' )

        def unhighlight( _event, link=self.link ):
            "Unhighlight item on mouse exit."
            self.canvas.itemconfig( link, fill='blue' )
            #self.selectItem( None )

        self.canvas.tag_bind( self.link, '<Enter>', highlight )
        self.canvas.tag_bind( self.link, '<Leave>', unhighlight )
        self.canvas.tag_bind( self.link, '<ButtonPress-1>', select )
        self.canvas.tag_bind( self.link, '<Button-3>', self.do_linkPopup )

    def drawLink( self, src, dst ):

        "Finish creating a link"
        w = self.findWidgetByName(src)
        item = self.widgetToItem[ w ]

        x, y = self.canvas.coords( item )
        self.link = self.canvas.create_line( x, y, x, y, width=4,
                                             fill='blue', tag='link' )
        self.linkx, self.linky = x, y
        self.linkWidget = w
        self.linkItem = item

        source = self.linkWidget
        c = self.canvas

        dest = self.findWidgetByName(dst)
        x, y = c.coords(self.widgetToItem[dest])

        if ( source is None or dest is None or source == dest
                or dest in source.links or source in dest.links ):
            return
        # For now, don't allow hosts to be directly linked
        stags = self.canvas.gettags( self.widgetToItem[ source ] )
        dtags = self.canvas.gettags( self.widgetToItem[ dest] )
        if (('Host' in stags and 'Host' in dtags) or
           ('Controller' in dtags and 'LegacyRouter' in stags) or
           ('Controller' in stags and 'LegacyRouter' in dtags) or
           ('Controller' in dtags and 'LegacySwitch' in stags) or
           ('Controller' in stags and 'LegacySwitch' in dtags) or
           ('Controller' in dtags and 'Host' in stags) or
           ('Controller' in stags and 'Host' in dtags) or
           ('Controller' in stags and 'Controller' in dtags)):
            return

        if 'Controller' in stags or 'Controller' in dtags:
            linkType='control'
            c.itemconfig(self.link, dash=(6, 4, 2, 4), fill='red')
            self.createControlLinkBindings()
        else:
            linkType='data'
            self.createDataLinkBindings()
        c.itemconfig(self.link, tags=c.gettags(self.link)+(linkType,))

        x, y = c.coords( self.widgetToItem[dest] )
        c.coords( self.link, self.linkx, self.linky, x, y )
        self.addLink( source, dest, linktype=linkType )

        # We're done
        self.link = self.linkWidget = None

    def addLink(self, source, dest, linktype='data', linkopts=None):
        "Add link to model."
        if linkopts is None:
            linkopts = {}
        source.links[dest] = self.link
        dest.links[source] = self.link
        self.links[self.link] = {'type': linktype,
                                 'src': source,
                                 'dest': dest,
                                 'linkOpts': linkopts}

    # Menu handlers

    def createMenubar( self ):
        "Create our menu bar."

        font = self.font

        mbar = Menu( self.top, font=font )
        self.top.configure( menu=mbar )

        fileMenu = Menu( mbar, tearoff=False )
        mbar.add_cascade( label="File", font=font, menu=fileMenu )
        fileMenu.add_command( label="Load Prefs.", font=font, command=self.loadPrefs )
        fileMenu.add_command( label="Save Prefs.", font=font, command=self.savePrefs )
        fileMenu.add_separator()
        fileMenu.add_command( label='Quit', command=self.quit, font=font )

        editMenu = Menu( mbar, tearoff=False )
        mbar.add_cascade( label="Edit", font=font, menu=editMenu )
        editMenu.add_command( label="Preferences", font=font, command=self.prefDetails)
        editMenu.add_command( label="Filters", font=font, command=self.filterDetails)

        runMenu = Menu( mbar, tearoff=False )
        mbar.add_cascade( label="Run", font=font, menu=runMenu )
        runMenu.add_command( label="Pause", font=font, command=lambda: self.doRun(runMenu) )
        runMenu.add_command( label="Clear", font=font, command=self.clearQueue )
        fileMenu.add_separator()
        runMenu.add_command( label='Show Interfaces Summary', font=font, command=self.intfInfo )
        runMenu.add_command( label='Show OVS Summary', font=font, command=self.ovsShow )
        runMenu.add_command( label='Root Terminal', font=font, command=self.rootTerminal )

        # Application menu
        appMenu = Menu( mbar, tearoff=False )
        mbar.add_cascade( label="Help", font=font, menu=appMenu )
        appMenu.add_command( label='About MiniNAM', command=self.about,
                             font=font)

    def convertJsonUnicode(self, text):
        "Some part of Mininet doesn't like Unicode"
        if isinstance(text, dict):
            return {self.convertJsonUnicode(key): self.convertJsonUnicode(value) for key, value in text.iteritems()}
        elif isinstance(text, list):
            return [self.convertJsonUnicode(element) for element in text]
        elif isinstance(text, unicode):
            return text.encode('utf-8')
        else:
            return text

    def savePrefs( self ):
        "Save preferences and filters."
        myFormats = [
            ('Config File','*.config'),
            ('All Files','*'),
        ]
        savingDictionary = {}
        fileName = tkFileDialog.asksaveasfilename(filetypes=myFormats ,title="Save preferences and filters as...")
        if len(fileName ) > 0:
            # Save Application preferences
            savingDictionary['preferences'] = self.appPrefs
            # Save Application filters
            savingDictionary['filters'] = self.appFilters

            try:
                f = open(fileName, 'wb')
                f.write(json.dumps(savingDictionary, sort_keys=True, indent=4, separators=(',', ': ')))
            # pylint: disable=broad-except
            except Exception as er:
                print er
            # pylint: enable=broad-except
            finally:
                f.close()

    def loadPrefs( self ):
        "Load command."
        c = self.canvas

        myFormats = [
            ('Config File','*.config'),
            ('All Files','*'),
        ]
        f = tkFileDialog.askopenfile(filetypes=myFormats, mode='rb')
        if f == None:
            return

        loadedPrefs = self.convertJsonUnicode(json.load(f))
        # Load application preferences
        if 'preferences' in loadedPrefs:
            self.appPrefs = dict(self.appPrefs.items() + loadedPrefs['preferences'].items())
        # Load application filters
        if 'filters' in loadedPrefs:
            self.appFilters = dict(self.appFilters.items() + loadedPrefs['filters'].items())
        f.close()

    def printdata( self ):
        #Convienience function to print interface data while developing
        keys = ["node", "type", "interface", "ip", "dgw", "link", "TXP", "RXP", "TXB", "RXB", "mac"]
        row_format = "{:>15}" * (len(keys) + 1)
        print row_format.format("", *keys)
        for data in self.intfData:
            list = []
            for key in keys:
                try:
                    list.append(data[key])
                except:
                    list.append("")
            print row_format.format("", *list)

    def doRun( self , menu):
        "Run command."
        if self.active:
            self.active = False
            menu.entryconfigure(0, label="Resume")
        else:
            self.active = True
            menu.entryconfigure(0, label="Pause")

    def about( self ):
        "Display about box."
        about = self.aboutBox
        if about is None:
            bg = 'white'
            about = Toplevel( bg='white' )
            about.title( 'About' )
            desc = self.appName + ': a real-time network animator for Mininet'
            version = 'MiniNAM ' + MININAM_VERSION
            author = 'Originally by: Ahmed Khalid <a.khalid@cs.ucc.ie>, July 2016'
            enhancements = 'Enhancements by: Ahmed Khalid, Nov 2017'
            www = 'https://www.ucc.ie/en/misl/research/software/mininam/'
            line1 = Label( about, text=desc, font='Helvetica 10 bold', bg=bg )
            line2 = Label( about, text=version, font='Helvetica 9', bg=bg )
            line3 = Label( about, text=author, font='Helvetica 9', bg=bg )
            line4 = Label( about, text=enhancements, font='Helvetica 9', bg=bg )
            line5 = Entry( about, font='Helvetica 9', bg=bg, width=len(www), justify=CENTER )
            line5.insert(0, www)
            line5.configure(state='readonly')
            line1.pack( padx=20, pady=10 )
            line2.pack(pady=10 )
            line3.pack(pady=10 )
            line4.pack(pady=10 )
            line5.pack(pady=10 )
            hide = ( lambda about=about: about.withdraw() )
            self.aboutBox = about
            # Hide on close rather than destroying window
            Wm.wm_protocol( about, name='WM_DELETE_WINDOW', func=hide )
        # Show (existing) window
        about.deiconify()

    def linkUp( self ):
        if ( self.selection is None or
             self.net is None):
            return
        link = self.selection
        linkDetail =  self.links[link]
        src = linkDetail['src']
        dst = linkDetail['dest']
        srcName, dstName = src[ 'text' ], dst[ 'text' ]
        self.net.configLinkStatus(srcName, dstName, 'up')
        self.canvas.itemconfig(link, dash=())

    def linkDown( self ):
        if ( self.selection is None or
             self.net is None):
            return
        link = self.selection
        linkDetail =  self.links[link]
        src = linkDetail['src']
        dst = linkDetail['dest']
        srcName, dstName = src[ 'text' ], dst[ 'text' ]
        self.net.configLinkStatus(srcName, dstName, 'down')
        self.canvas.itemconfig(link, dash=(4, 4))

    def prefDetails( self ):
        prefDefaults = self.appPrefs
        prefBox = PrefsDialog(self, title='Preferences', prefDefaults=prefDefaults)
        if prefBox.result:
            self.appPrefs = prefBox.result
        if self.appPrefs['startCLI']== 1:
            self.startCLI()

    def filterDetails( self ):
        filterDefaults = self.appFilters
        filterBox = FiltersDialog(self, title='Filters', filterDefaults=filterDefaults)
        if filterBox.result:
            self.appFilters = filterBox.result

    def listBridge( self, _ignore=None ):
        if ( self.selection is None or
             self.net is None or
             self.selection not in self.itemToWidget ):
            return
        name = self.itemToWidget[ self.selection ][ 'text' ]
        tags = self.canvas.gettags( self.selection )

        if name not in self.net.nameToNode:
            return
        if 'Switch' in tags or 'LegacySwitch' in tags:
            call(["xterm -T 'Bridge Details' -sb -sl 2000 -e 'ovs-vsctl list bridge " + name + "; read -p \"Press Enter to close\"' &"], shell=True)

    def intfInfo( self ):

        info = self.infoBox
        if info is None:
            info = Toplevel( bg='white')
            info.title( 'Interfaces' )

            columns = 9
            font = 'Helvetica 10 bold'
            widgets = []
            Label(info, text='Interface', borderwidth=0, font=font, padx=10).grid(row=0, column=0, sticky="nsew", padx=1, pady=1)
            Label(info, text='Linked To', borderwidth=0, font=font, padx=10).grid(row=0, column=1, sticky="nsew", padx=1, pady=1)
            Label(info, text='Node Type', borderwidth=0, font=font, padx=10).grid(row=0, column=2, sticky="nsew", padx=1, pady=1)
            Label(info, text='IP Address', borderwidth=0, font=font, padx=10).grid(row=0, column=3, sticky="nsew", padx=1, pady=1)
            Label(info, text='MAC Address', borderwidth=0, font=font, padx=10).grid(row=0, column=4, sticky="nsew", padx=1, pady=1)
            Label(info, text='TXP', borderwidth=0, font=font, padx=10).grid(row=0, column=5, sticky="nsew", padx=1, pady=1)
            Label(info, text='RXP', borderwidth=0, font=font, padx=10).grid(row=0, column=6, sticky="nsew", padx=1, pady=1)
            Label(info, text='TXB', borderwidth=0, font=font, padx=10).grid(row=0, column=7, sticky="nsew", padx=1, pady=1)
            Label(info, text='RXB', borderwidth=0, font=font, padx=10).grid(row=0, column=8, sticky="nsew", padx=1, pady=1)
            row = 0
            font = 'Helvetica 9'
            infoOrder = ['interface', 'link', 'type', 'ip', 'mac', 'TXP', 'RXP', 'TXB', 'RXB']
            for data in self.intfData:
                row += 1
                current_row = []
                for column in range(columns):
                    label = Label(info, text=data[infoOrder[column]], borderwidth=0, font=font, padx=5)
                    label_name = 'label_'+ infoOrder[column]
                    data[label_name] = label
                    label.grid(row=row, column=column, sticky="nsew", padx=1, pady=1)
                    current_row.append(label)
                widgets.append(current_row)

            for column in range(columns):
                info.columnconfigure(column, weight=1)
            # Scroll bars
            ybar = Scrollbar(info, orient='vertical')
            ybar.grid(row=0, rowspan=row+1, column=9, sticky='ns')

            hide = (lambda info=info: info.withdraw())
            self.infoBox = info
            # Hide on close rather than destroying window
            Wm.wm_protocol(info, name='WM_DELETE_WINDOW', func=hide)
        # Show (existing) window
        self.updateIntfInfo()
        info.deiconify()

    def updateIntfInfo (self):
        self.printdata()
        items = ['interface', 'link', 'type', 'ip', 'mac',
                  'TXP', 'RXP', 'TXB', 'RXB', ]
        for data in self.intfData:
            for item in items:
                data[str('label_' + item)].config(text=str(data[item]))

    def startCLI(self):
        # Don't start a second CLI thread if it already exists
        if self.cli is None:
            self.cli = Thread(target=CLI, args=(self.net,))
            self.cli.daemon = True
            self.cli.start()
        elif not self.cli.isAlive():
            self.cli = Thread(target=CLI, args=(self.net,))
            self.cli.daemon = True
            self.cli.start()

    @staticmethod
    def ovsShow( _ignore=None ):
        call(["xterm -T 'OVS Summary' -sb -sl 2000 -e 'ovs-vsctl show; read -p \"Press Enter to close\"' &"], shell=True)

    @staticmethod
    def rootTerminal( _ignore=None ):
        call(["xterm -T 'Root Terminal' -sb -sl 2000 &"], shell=True)

    def do_linkPopup(self, event):

        # display the popup menu
        if self.net:
            try:
                self.linkPopup.post(event.x_root, event.y_root)
                self.linkPopup.focus_set()
            finally:
                # make sure to release the grab (Tk 8.0a1 only)
                self.linkPopup.grab_release()

    def do_controllerPopup(self, event):
        # do nothing
        return

    def do_legacyRouterPopup(self, event):
        # display the popup menu
        if self.net:
            try:
                self.legacyRouterPopup.post(event.x_root, event.y_root)
                self.legacyRouterPopup.focus_set()
            finally:
                # make sure to release the grab (Tk 8.0a1 only)
                self.legacyRouterPopup.grab_release()

    def do_hostPopup(self, event):

        # display the popup menu
        if self.net:
            try:
                self.hostPopup.post(event.x_root, event.y_root)
                self.hostPopup.focus_set()
            finally:
                # make sure to release the grab (Tk 8.0a1 only)
                self.hostPopup.grab_release()

    def do_legacySwitchPopup(self, event):
        # display the popup menu
        if self.net:
            try:
                self.switchPopup.post(event.x_root, event.y_root)
                self.switchPopup.focus_set()

            finally:
                # make sure to release the grab (Tk 8.0a1 only)
                self.switchPopup.grab_release()

    def do_switchPopup(self, event):
        # display the popup menu
        if self.net:
            try:
                self.switchPopup.post(event.x_root, event.y_root)
                self.switchPopup.focus_set()
            finally:
                # make sure to release the grab (Tk 8.0a1 only)
                self.switchPopup.grab_release()

    # Model interface

    def xterm( self, _ignore=None ):
        "Make an xterm when a button is pressed."
        if ( self.selection is None or
             self.net is None or
             self.selection not in self.itemToWidget ):
            return
        name = self.itemToWidget[ self.selection ][ 'text' ]
        if name not in self.net.nameToNode:
            return
        term = makeTerm( self.net.nameToNode[ name ], 'Host', term=self.appPrefs['terminalType'] )
        if StrictVersion(MININET_VERSION) > StrictVersion('2.0'):
            self.net.terms += term
        else:
            self.net.terms.append(term)

    def iperf( self, _ignore=None ):
        "Make an xterm when a button is pressed."
        if ( self.selection is None or
             self.net is None or
             self.selection not in self.itemToWidget ):
            return
        name = self.itemToWidget[ self.selection ][ 'text' ]
        if name not in self.net.nameToNode:
            return
        self.net.nameToNode[ name ].cmd( 'iperf -s -p 5001 &' )


    @staticmethod
    def pathCheck( *args, **kwargs ):
        "Make sure each program in *args can be found in $PATH."
        moduleName = kwargs.get( 'moduleName', 'it' )
        for arg in args:
            if not quietRun( 'which ' + arg ):
                showerror(title="Error",
                      message= 'Cannot find required executable %s.\n' % arg +
                       'Please make sure that %s is installed ' % moduleName +
                       'and available in your $PATH.' )

    def stop( self ):

        #Reset the terminal even if CLI wasn't exited properly
        os.system('stty sane')
        #Clear the packet queues
        for q in self.flowQueues:
            self.flowQueues[q].queue.clear()

        #Stop network.
        if self.net:
            self.net.stop()

        cleanUpScreens()

        self.net = None

    def quit( self ):
        "Stop our network, if any, then quit."
        self.stop()

        Frame.quit( self )

def miniImages():
    "Create and return images for MiniNAM."

    # Image data. Git will be unhappy. However, the alternative
    # is to keep track of separate binary files, which is also
    # unappealing.

    return {
        'Select': BitmapImage(
            file='/usr/include/X11/bitmaps/left_ptr' ),

        'Switch': PhotoImage( data=r"""
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
            """),

        'LegacySwitch': PhotoImage( data=r"""
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
4BE2eIRYeHAEIBwBP0Y4Qn41YWRSCQgAOw==
            """),

        'LegacyRouter': PhotoImage( data=r"""
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
gGPLHwLwcMIo12Qxu0ABAQA7
            """),

        'Controller': PhotoImage( data=r"""
            R0lGODlhMAAwAPcAAAEBAWfNAYWFhcfHx+3t6/f390lJUaWlpfPz8/Hx72lpaZGRke/v77m5uc0B
            AeHh4e/v7WNjY3t7e5eXlyMjI4mJidPT0+3t7f///09PT7Ozs/X19fHx8ZWTk8HBwX9/fwAAAAAA
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEAAAAALAAAAAAwADAA
            Bwj/AAEIHEiwoMGDCBMqXMiwocOHECNKnEixosWLGAEIeMCxo8ePHwVkBGABg8mTKFOmtDByAIYN
            MGPCRCCzQIENNzEMGOkBAwIKQIMKpYCgKAIHCDB4GNkAA4OnUJ9++CDhQ1QGFzA0GKkBA4GvYMOK
            BYtBA1cNaNOqXcuWq8q3b81m7Cqzbk2bMMu6/Tl0qFEEAZLKxdj1KlSqVA3rnet1rOOwiwmznUzZ
            LdzLJgdfpIv3pmebN2Pm1GyRbocNp1PLNMDaAM3Im1/alQk4gO28pCt2RdCBt+/eRg8IP1AUdmmf
            f5MrL56bYlcOvaP7Xo6Ag3HdGDho3869u/YE1507t+3AgLz58ujPMwg/sTBUCAzgy49PH0LW5u0x
            XFiwvz////5dcJ9bjxVIAHsSdUXAAgs2yOCDDn6FYEQaFGDgYxNCpEFfHHKIX4IDhCjiiCSS+CGF
            FlCmogYpcnVABTDGKGOMAlRQYwUHnKjhAjX2aOOPN8LImgAL6PiQBhLMqCSNAThQgQRGOqRBBD1W
            aaOVAggnQARRNqRBBxmEKeaYZIrZQZcMKbDiigqM5OabcMYp55x01ilnQAA7
            """),

        'Host': PhotoImage( data=r"""
            R0lGODlhIAAYAPcAMf//////zP//mf//Zv//M///AP/M///MzP/M
            mf/MZv/MM//MAP+Z//+ZzP+Zmf+ZZv+ZM/+ZAP9m//9mzP9mmf9m
            Zv9mM/9mAP8z//8zzP8zmf8zZv8zM/8zAP8A//8AzP8Amf8AZv8A
            M/8AAMz//8z/zMz/mcz/Zsz/M8z/AMzM/8zMzMzMmczMZszMM8zM
            AMyZ/8yZzMyZmcyZZsyZM8yZAMxm/8xmzMxmmcxmZsxmM8xmAMwz
            /8wzzMwzmcwzZswzM8wzAMwA/8wAzMwAmcwAZswAM8wAAJn//5n/
            zJn/mZn/Zpn/M5n/AJnM/5nMzJnMmZnMZpnMM5nMAJmZ/5mZzJmZ
            mZmZZpmZM5mZAJlm/5lmzJlmmZlmZplmM5lmAJkz/5kzzJkzmZkz
            ZpkzM5kzAJkA/5kAzJkAmZkAZpkAM5kAAGb//2b/zGb/mWb/Zmb/
            M2b/AGbM/2bMzGbMmWbMZmbMM2bMAGaZ/2aZzGaZmWaZZmaZM2aZ
            AGZm/2ZmzGZmmWZmZmZmM2ZmAGYz/2YzzGYzmWYzZmYzM2YzAGYA
            /2YAzGYAmWYAZmYAM2YAADP//zP/zDP/mTP/ZjP/MzP/ADPM/zPM
            zDPMmTPMZjPMMzPMADOZ/zOZzDOZmTOZZjOZMzOZADNm/zNmzDNm
            mTNmZjNmMzNmADMz/zMzzDMzmTMzZjMzMzMzADMA/zMAzDMAmTMA
            ZjMAMzMAAAD//wD/zAD/mQD/ZgD/MwD/AADM/wDMzADMmQDMZgDM
            MwDMAACZ/wCZzACZmQCZZgCZMwCZAABm/wBmzABmmQBmZgBmMwBm
            AAAz/wAzzAAzmQAzZgAzMwAzAAAA/wAAzAAAmQAAZgAAM+4AAN0A
            ALsAAKoAAIgAAHcAAFUAAEQAACIAABEAAADuAADdAAC7AACqAACI
            AAB3AABVAABEAAAiAAARAAAA7gAA3QAAuwAAqgAAiAAAdwAAVQAA
            RAAAIgAAEe7u7t3d3bu7u6qqqoiIiHd3d1VVVURERCIiIhEREQAA
            ACH5BAEAAAAALAAAAAAgABgAAAiNAAH8G0iwoMGDCAcKTMiw4UBw
            BPXVm0ixosWLFvVBHFjPoUeC9Tb+6/jRY0iQ/8iVbHiS40CVKxG2
            HEkQZsyCM0mmvGkw50uePUV2tEnOZkyfQA8iTYpTKNOgKJ+C3AhO
            p9SWVaVOfWj1KdauTL9q5UgVbFKsEjGqXVtP40NwcBnCjXtw7tx/
            C8cSBBAQADs=
        """ ),

        'OldSwitch': PhotoImage( data=r"""
            R0lGODlhIAAYAPcAMf//////zP//mf//Zv//M///AP/M///MzP/M
            mf/MZv/MM//MAP+Z//+ZzP+Zmf+ZZv+ZM/+ZAP9m//9mzP9mmf9m
            Zv9mM/9mAP8z//8zzP8zmf8zZv8zM/8zAP8A//8AzP8Amf8AZv8A
            M/8AAMz//8z/zMz/mcz/Zsz/M8z/AMzM/8zMzMzMmczMZszMM8zM
            AMyZ/8yZzMyZmcyZZsyZM8yZAMxm/8xmzMxmmcxmZsxmM8xmAMwz
            /8wzzMwzmcwzZswzM8wzAMwA/8wAzMwAmcwAZswAM8wAAJn//5n/
            zJn/mZn/Zpn/M5n/AJnM/5nMzJnMmZnMZpnMM5nMAJmZ/5mZzJmZ
            mZmZZpmZM5mZAJlm/5lmzJlmmZlmZplmM5lmAJkz/5kzzJkzmZkz
            ZpkzM5kzAJkA/5kAzJkAmZkAZpkAM5kAAGb//2b/zGb/mWb/Zmb/
            M2b/AGbM/2bMzGbMmWbMZmbMM2bMAGaZ/2aZzGaZmWaZZmaZM2aZ
            AGZm/2ZmzGZmmWZmZmZmM2ZmAGYz/2YzzGYzmWYzZmYzM2YzAGYA
            /2YAzGYAmWYAZmYAM2YAADP//zP/zDP/mTP/ZjP/MzP/ADPM/zPM
            zDPMmTPMZjPMMzPMADOZ/zOZzDOZmTOZZjOZMzOZADNm/zNmzDNm
            mTNmZjNmMzNmADMz/zMzzDMzmTMzZjMzMzMzADMA/zMAzDMAmTMA
            ZjMAMzMAAAD//wD/zAD/mQD/ZgD/MwD/AADM/wDMzADMmQDMZgDM
            MwDMAACZ/wCZzACZmQCZZgCZMwCZAABm/wBmzABmmQBmZgBmMwBm
            AAAz/wAzzAAzmQAzZgAzMwAzAAAA/wAAzAAAmQAAZgAAM+4AAN0A
            ALsAAKoAAIgAAHcAAFUAAEQAACIAABEAAADuAADdAAC7AACqAACI
            AAB3AABVAABEAAAiAAARAAAA7gAA3QAAuwAAqgAAiAAAdwAAVQAA
            RAAAIgAAEe7u7t3d3bu7u6qqqoiIiHd3d1VVVURERCIiIhEREQAA
            ACH5BAEAAAAALAAAAAAgABgAAAhwAAEIHEiwoMGDCBMqXMiwocOH
            ECNKnEixosWB3zJq3Mixo0eNAL7xG0mypMmTKPl9Cznyn8uWL/m5
            /AeTpsyYI1eKlBnO5r+eLYHy9Ck0J8ubPmPOrMmUpM6UUKMa/Ui1
            6saLWLNq3cq1q9evYB0GBAA7
        """ ),

        'NetLink': PhotoImage( data=r"""
            R0lGODlhFgAWAPcAMf//////zP//mf//Zv//M///AP/M///MzP/M
            mf/MZv/MM//MAP+Z//+ZzP+Zmf+ZZv+ZM/+ZAP9m//9mzP9mmf9m
            Zv9mM/9mAP8z//8zzP8zmf8zZv8zM/8zAP8A//8AzP8Amf8AZv8A
            M/8AAMz//8z/zMz/mcz/Zsz/M8z/AMzM/8zMzMzMmczMZszMM8zM
            AMyZ/8yZzMyZmcyZZsyZM8yZAMxm/8xmzMxmmcxmZsxmM8xmAMwz
            /8wzzMwzmcwzZswzM8wzAMwA/8wAzMwAmcwAZswAM8wAAJn//5n/
            zJn/mZn/Zpn/M5n/AJnM/5nMzJnMmZnMZpnMM5nMAJmZ/5mZzJmZ
            mZmZZpmZM5mZAJlm/5lmzJlmmZlmZplmM5lmAJkz/5kzzJkzmZkz
            ZpkzM5kzAJkA/5kAzJkAmZkAZpkAM5kAAGb//2b/zGb/mWb/Zmb/
            M2b/AGbM/2bMzGbMmWbMZmbMM2bMAGaZ/2aZzGaZmWaZZmaZM2aZ
            AGZm/2ZmzGZmmWZmZmZmM2ZmAGYz/2YzzGYzmWYzZmYzM2YzAGYA
            /2YAzGYAmWYAZmYAM2YAADP//zP/zDP/mTP/ZjP/MzP/ADPM/zPM
            zDPMmTPMZjPMMzPMADOZ/zOZzDOZmTOZZjOZMzOZADNm/zNmzDNm
            mTNmZjNmMzNmADMz/zMzzDMzmTMzZjMzMzMzADMA/zMAzDMAmTMA
            ZjMAMzMAAAD//wD/zAD/mQD/ZgD/MwD/AADM/wDMzADMmQDMZgDM
            MwDMAACZ/wCZzACZmQCZZgCZMwCZAABm/wBmzABmmQBmZgBmMwBm
            AAAz/wAzzAAzmQAzZgAzMwAzAAAA/wAAzAAAmQAAZgAAM+4AAN0A
            ALsAAKoAAIgAAHcAAFUAAEQAACIAABEAAADuAADdAAC7AACqAACI
            AAB3AABVAABEAAAiAAARAAAA7gAA3QAAuwAAqgAAiAAAdwAAVQAA
            RAAAIgAAEe7u7t3d3bu7u6qqqoiIiHd3d1VVVURERCIiIhEREQAA
            ACH5BAEAAAAALAAAAAAWABYAAAhIAAEIHEiwoEGBrhIeXEgwoUKG
            Cx0+hGhQoiuKBy1irChxY0GNHgeCDAlgZEiTHlFuVImRJUWXEGEy
            lBmxI8mSNknm1Dnx5sCAADs=
        """ ),

        'Logo': PhotoImage(
            data="iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAYAAAD0eNT6AABpJklEQVR42u2dB3wT5/nHSy1jIVSR0bRNR9L0n678k3/bNE3SNm3IJCTsGabBtpaNCStskI0tyWww2GyzCXsPY4MNls6YDWET9gp7Ezb6+xV35ozt00mWdO/d/d7P5z4prvS19Ep+vs/dve/z/OhHGBgYGBgYGBj+jo8/rlml+Pgx76gCHnjggQceeODJi+fvL494+gAPPPDAAw888OTF8zfr0BQfkbxDE2j2AR544IEHHnjghZ8XyC8nv7Aq74is5JsBDzzwwAMPPPDCyAvkl0cVH1reEVXJNwMeeOCBBx544IWRF8gvJ7+wGu/QVvLNgAceeOCBBx54YeRxTLEPJKsLdcVHdd5B/v3jAH8xeOCBBx544IEXfl4VdtHgj8X+cvIL9byjeiXfDHjggQceeOCBF14et4DQdwLA++UG3qGv5JvRgwceeOCBBx54YeVV4e0aEE4A2AfreC+gBvvfyrwZjlMDPPDAAw888MALC49bQFiVlwBUEXqwlnfpwYDJBg888MADDzxZ8rhdAyUJgK9ModpT9x4w2eCBBx544IEnL56Ot2uAJAAaX/cItLwEoDomGzzwwAMPPPBkx+McziUAkUKX/jVshsAlADpMNnjggQceeODJjsffNVBNsGgQuyggkpcAaDHZ4IEHHnjggSdLnoGXAGh9LfrjJwCVKVeIDw888MADDzzwpOVxCYBO0OfskyJ4ewQhf/DAAw888MCTL88gag0fLwHQQP7ggQceeOCBJ3ueuN17vAQA8gcPPPDAAw88tfAq2VEIkw0eeOCBBx54MudhcsADDzzwwAMP8sfkgAceeOCBBx7kj8kGDzzwwAMPPMgfkw0eeOCBBx54kD944IEHHnjggQf5gwceeOCBBx54NMpf9O4/TDZ44IEHHnjgKYLHlf4XXSRIj8kGDzzwwAMPPNnLXyMqAeD1EzZgssEDDzzwwANP1vLn+v0IJwDsg3Xs2b8Bkw0eeOCBBx54spV/FNvtN1Kw9D/7YC179q/n9RbGZIMHHnjggQeevHha9ihJAHxlCtV4CYAekw0eeOCBBx54suPpWJ9zCYDG1z0CLS8BqI7JBg888MADDzzZ8TiHcwlApNClfw2bIXAJgA6TDR544IEHHniy43FX77kEIEpI/hFsdlCVd78Akw0eeOCBBx548uMZeAmA1teiP34CECW6ShAmGzzwwAMPPPBo43EJgE7Q5+yTInh7BCF/8MADDzzwwJMvzyBqDR8vAdBA/uCBBx544IEne5643Xu8BADyBw888MADDzy18AIVPyYbPPDAAw888JTBw+SABx544IEHHuSPyQEPPPDAAw88yB+TDR544IEHHniQPyYbPPDAAw888CB/8MADDzzwwAMP8gcPPPDAAw888GiUv+jdf5hs8MADDzzwwFMEjyv9L7pIkB6TDR544IEHHniyl79GVALA6ydswGSDBx544IEHnqzlz/X7EU4A2Afr2LN/AyYbPPDAAw888GQr/yi222+kYOl/9sFa9uxfz+stjMkGDzzwwAMPPHnxtOxRkgD4yhSq8RIAPSYbPPDAAw888GTH07E+5xIAja97BFpeAlAdkw0eeOCBBx54suNxDucSgEihS/8aNkPgEgAdJhs88MADDzzwZMfjrt5zCUCUkPwj2OygKu9+ASYbPPDAAw888OTHM/ASAK2vRX/8BCBKdJUgTDZ44IEHHnjg0cbjEgCdoM/ZJ0Xw9ghC/uCBBx544IEnX55B1Bo+XgKggfzBAw888MADT/Y8cbv3eAkA5A8eeOCBBx54auEFKn5MNnjggQceeOApg4fJAQ888MADDzzIH5MDHnjggQceeJA/Jhs88MADDzzwIH9MNnjggQceeOBB/uCBBx544IEHHuQPHnjggQceeODRKH/Ru/8w2eCBBx544IGnCB5X+l90kSA9Jhs88MADDzzwZC9/jagEgNdP2IDJBg888MADDzxZy5/r9yOcALAP1rFn/wZMNnjggQceeODJVv5RbLffSMHS/+yDtezZv57XWxiTDR54FPNsNs+Pjbblz0d3nfLX9j1mfBTTZ0GzuH5LLUbbit4Wu8thdTCZVod7ktnBTLc63XMtdmaxxeleZbW71hb/b5fZ6dpktTM7rE7XruKfb7U6mUKzw7U+bkDuWlPy6mxjcs5SY3L2PFNyzkxzasF4i5MZWvy43ua0QnPxfxsXP79mMed1Y+r6F5vadlfF5wseeFTwtOxRkgD4yhSq8RIAPSYbPPAk5nk8VYrF/GxCauGbxcJuVCzfrsUyH10s6OVmO7Pb7GTOW1PdD8wpeR5zylrekecpfpynWOb+H8XPqxTPzlwvfp1Hiv93gcXhnmq2uwYY+y+ztus1+4s2iWNeb9CgxfP4fMEDL6Q8HetzLgHQ+LpHoOUlANUx2eCBFz5ea9u0KHIWbXEWtiw+S08jZ+nkrLz47PpaSGUtAc+Ykne/ODE44r0C4WTGF7/fRHIVIXZo4XP4voAHXqV5nMO5BCBS6NK/hs0QuARAh8kGD7zQ8Go2qFOjdceRf2rfZ36jONvyfnHJObOLz+Z3FsvwHo2yDj/PdcrqYFaSJMjscLdKcBa+wd1WwPcPPPB88rir91wCECUk/wg2O6jKu1+AyQYPvCDxEkeujLKmMf8yOwq6G5Nyl5uTc84rR9Zh4pHkyF6w0Zi0enRM34VtWnVM/wO+f+CBVy7PwEsAtL4W/fETgCjRVYIw2eCBV77w7QUvxDvd9S1OZmDxWazbbGfuqErW4bqNkLz2qNVRMN27ENHOvE4WQuL7Bx54JQmATtDn7JMieHsEIX/wwPOTZ7Jt0VnSXLUtDibd6mD2Q9YS8eyuq8X/XVL8c0t8CvMyvs/gqZRnELWGj5cAaCB/8MATyfN4qlgGuv9YLJuvrA5XdvF/b0PWNPJc+4qTsmHmNNcn5DYMvs/gqYQnbvceLwGA/MEDT4AXbcvXFsukjsXpzmC3t0HWsuK5bpnt61fE2VZ0bdkp43X8fYCnel6g4sdkg6cGXu2mCc+bU9fX8xbPsTPXIVfl8EzJuZvi+q/qGZ+S9xL+PsBTOw+TAx54xZw6X7b/aWzvBY2NSTkzzA73FchV+TxSCZHUISBVDPH3AR7kj8kBT0W8L75o/kxsz3n1jLbsqeYBuZchV5Xy7K5HVjuTb3G6rQmOjc/j7wM8yB+TDZ5CeXG2Nb+JS1qVYkrOOQ4ZgvfUmoG7VofrG4uT+ZDbXoi/N/Agf0w2eDLm2Wz5muLgXtdidy0zpqx5CBmC55vFHDI7Xb1ad8p8FX9v4EH+mGzwZMYzOzf8tjj4p5jtzGnIELxAeMaUtfdNttXL2ved16RWs0bP4u8NPMgfPPBo5Xk8VeLtzEfFQXyF9/4uZAhesHip7uNWB9PNlLalBv7ewJOT/EXv/sNkgydHnmnclkjSRMbsZLZDXuCFlPe47fFQU5rrJfz9gkc5jyv9L7pIkB6TDZ5ceORsjJyVWeyuk5AXeGHl2ZkHFqd7VkJq4Zv4+wWPUvlrRCUAvH7CBkw2eLTzyNkXOQursFgP5AVeGHlmJ5NX/N8vsHsAPIrkz/X7EU4A2Afr2LN/AyYbPFp5pOFLsfgnkrMvyAs82ngWu+tbS8r6hjUb1KmBv1/wJJR/FNvtN1Kw9D/7YC179q/n9RbGZINHDc+cWvgrq4PJ9PaIh2zAo5xnGpC7vX3v+U1r1v/iGfz9ghdmnpY9ShIAX5lCNV4CoMdkg0cLL9a+4edWp3u42c7cgWzAkxvPNGDNRou94FOyOwXxALww8HSsz7kEQOPrHoGWlwBUx2SDRwOPlGW1OJmBpKMbZAOe3Hlmp3udxe7+D+IBeCHkcQ7nEoBIoUv/GjZD4BIAHSYbPKl5nYcWVisWf1+/OvFBNuDJhedwZcenuf4X8QC8IPO4q/dcAhAlJP8INjuoyrtfgMkGTzLeX2x9I8xprmZmp+sYZAOeonlkAavDPbq85kOIB+AFyDPwEgCtr0V//AQgSnSVIEw2eCHgWZPXvVUcGAsgB/BUtXXQzly2OJiOpIgV4gF4leRxCYBO0OfskyJ4ewQhf/Ak4ZFGKxZ7QVZJyV7IATwV8sx2116zY31txBfwKsEziFrDx0sANJA/eFLwGrSK/Zmx/8p+1lT3dcgBPPAe8+KSs7Oju0z4O+ILeAHwxO3e4yUAkD94Yee17zX7U2Ny7n7IATzwyuPl3o2zrUpt8NUCLeILeEHnBSp+TDZ4leE1j7b92mhbNd6cvOYR5AAeeMI8s53ZbUlzvYv4Al6oeJgc8MLCi+m9sLkpOec05AAeeP50HSRrY1wj4235esQX8CB/8GTFa5E45FVT0qr5CObggVeproPHLWmu2ogv4EH+4FHPI41QYvsutpoH5F5GMAcPvCDxHO6ZifaCFxCvwIP8waOS92XHQa8YbTkrEMzBAy8EPLvrHHc1APEKPMgfPGp4sX0WNDAm555FMAcPvNDyzHbXqKbtuv4M8Qo8yB88SXktuszQmZKzMxDMwQMvnC2Hc/a2/3ravxCvwBPBrILJAS/oPNOA/P8zJefuRjAHDzyJ6gb0X9WzXbsJGsQr8MoTP1v3R3SRID0mGzyfw+OpYrYXfGVMzruDYA4eeBLXDXAyq42p619EvALvKflrRCUAvH7CBkw2eELD6nQ9a3UULEfwBQ88muoGMBfMaa5PEK/AY+XP9fsRTgDYB+vYs38DJhu8CuVv3/B/5lT3YQRf8MCjj2d2uh5a0pie5Aod4pWq5R/FdvuNFCz9zz5Yy57963m9hTHZ4JUaZoe7lTm14AcEX/DAo5xndy9MtBUZEP9UydOyR0kC4CtTqMZLAPSYbPBKLfQbtyWSlCRF8AUPPBnxHMx+s73gNcQ/VfF0rM+5BEDj6x6BlpcAVMdkg8cfZGGRxc64EHzBA09+PLOTuRFvZ5og/qmCxzmcSwAihS79a9gMgUsAdJhs8Epd8rcX/rs4iJxB8AUPPHnzjEnZIxo0aPE84p9iedzVey4BiBKSfwSbHVTl3S/AZIPHW+nvbm21u+4h+IIHnjJ4puSc1U3adP8V4p8ieQZeAqD1teiPnwBEia4ShMlWPs/jqWJxMP0QfMEDT4G85JydltScXyP+KY7HJQA6QZ+zT4rg7RGE/MErWexndrqyECzBA0+5PIvddTLBWfgG4p+ieAZRa/h4CYAG8gePG1/Z8p+xOF1rECzBA08VRYOuF//7U8Q/xfDE7d7jJQCQP3jeEZ/CvGy2M7sRLMEDT0U8O/PAanfFIp6qiBeo+DHZyuRZna6/m+3u7xEswQNPpTwHYy+vciDiKVoEY7KVfObvZP5L9gkjWIIHnsp5dmZC07lzIxBPIX9Mtgp4ljSmltnu+gHBEjzwwGM5M8lCYMRTyB+TrWCe2VnY0LvHH8ESPPDA4x2WVNeShm1MP0U8hfwx2Uo883cWtvQu/kGwBA888MrhxQ3IWduw5dcvIp5C/phsRcnfHVd85v8IwRI88MAT4pkG5BZ+2T7lV4inkD8mWxGr/ZmvENzAAw88sTyzo2BT7NDC5xBP5S9/0bv/MNkKlL+D6YbgBh544PnNszM7/EkCEJ+p43Gl/0UXCdJjshUl/3gEN/DAAy9gnsO1MdFWZEA8laX8NaISAF4/YQMmWyH3/B2uaAQ38MADr7I8i9213mTbokN8lpX8uX4/wgkA+2Ade/ZvwGQr4Z5/YVOz0/UQwQ088MALTsVAV3biyJVRiM+ykH8U2+03UrD0P/tgLXv2r+f1FsZky/bMn6ljdjL3EdzAAw+8YPLMTvciUiwI8ZlqnpY9ShIAX5lCNV4CoMdky5cXb2c+MtuZOwhu4IEHXqgqBpKywYjPVPJ0rM+5BEDj6x6BlpcAVMdky5dnthf+2+p03UJwAw888EJcMXBizQZ1aiA+U8XjHM4lAJFCl/41bIbAJQA6TLaM7/mnbfiz2clcQXADDzzwwsEzJq0YiPhMDY+7es8lAFFC8o9gs4OqvPsFmGyZ8mLtG35utbuOIriBBx544eTF9Vsaj/hMBc/ASwC0vhb98ROAKNFVgjDZ1PHI1hyyTxfBCDzwwAs3z5iSd9+asv4TxGfJeVwCoBP0OfukCN4eQchfpjyyEMdqdy9EMAIPPPCk4pmdrmsWO/M64rOkPIOoNXy8BEAD+cubZ3EwwxCMwAMPPMl5dua4MXX9i4jPkvH0/pT7jYD85c0zO1wdEIzAAw88inhbug5eXR3xmWJeoOLHZNPDszpddb1V/hCMwAMPPIp4FgezlNyaRLxHi2DwQiH/x9v9biAYgQceeDTyLE7GgXgP+YMXZF7MQPdPis/+9yEYgQceeFTz7EwDxHvIH7xg8TyeKsV/VPMRjMADDzzqeXbmumWg+4+I95A/eEHgWe3u7ghG4IEHnox4e5pG934R8R7yB68SPG+DH0fBQwQj8MADT048U3L2opr1v3gG8R7yBy8AninN9ZI11X0BwQg88MCTZblg24o+iPfSyl/07j9MNj28aFu+1mp3b0YwAg888GTLS857YElZ9xHivSQ8rvS/6CJBekw2HTyLwzUawQg88MCTPc/uOmcZzPwM8T7s8teISgB4/YQNmGzpeabUdXUQPMADDzyl8MwO13KymwnxPmzy5/r9CCcA7IN17Nm/AZMtLa+dLfdFc3LueQQP8MADT1E8BxOPeB8W+Uex3X4jBUv/sw/Wsmf/el5vYUy2BLy/2PpGmAbkrkbwAA888BTIu222F7yGeB9SnpY9ShIAX5lCNV4CoMdkS8eLs63oiuABHnjgKZZnZ3YkjlwZhXgfEp6O9TmXAGh83SPQ8hKA6phs6Xhtu039R/Ef0W0ED/DAA0/RPId7CPwRdB7ncC4BiBS69K9hMwQuAdBhsqXjNWxj+qkpKXcXggd44IGnDl7hx/BH0Hjc1XsuAYgSkn8Emx1U5d0vwGRLyItLWpmO4AEeeOCpiHemnT37p/BHUHgGXgKg9bXoj58ARImuEoTJDgkvuuc3HxpTch8ieIAHHnhq4sUlZ0+HP4LC4xIAnaDP2SdF8PYIQv4S8mo3sbxgTMrZg+ABHnjgqZEX03t+ffij0jyDqDV8vARAA/lLzzP2X5GC4AEeeOCplWdMXnO0UeteP4c/KsXT+1PuNwLyl57Xusvkf5hTcu8ieIAHHnhq5lnsrsHwRxh4gYofkx1c3uefN33WNCC3EMEDPPDAUzvP7HQ9tDpdf4c/wsfD5EjIi7Et74TgAR544IHH9gpwMttN47ZEwh+Qv6J5LTuM/rMxZc11BA/wwAMPvCeHxcH0gD8gf0XzjANyl+CPHTzwwAOvbK8Aq9P1O/gD8lckL6bPgjr4YwcPPPDAK/+wOJkF8Afkrzhew4atn7WkFnyLP3bwwAMPvIoPs9NVE/6A/BXFs9jXW/HHDh544IHH+OwY2HTu3Aj4IzjyF737D5MdGl58z8XPFX+pL+CPveKjx8gNnjPnr3qOnDjrOXz8TMlB/k1+/v2Fa34fNPKW5u2DHETwRszYIsvP1x9eWtYmxIOKDxP8UWkeV/pfdJEgPSY7+DyLgxkG+QsfSWM2eG7duuW5efNmyUH+/fDhQ08ggzyPRt6Fyzc8bXougPx98Nxbj8ry8/WHlzZ2lceUko94UN5tAIf7fKvYlN/AH5WSv0ZUAsDrJ2zAZAdZ/gPdfzQ7mfuQvzDPPt6lePlzo2PSLE/rbrMh/wp4HQYynlu37ypa/mSkT1nraRQ/wROXlIt4UA4vLmnVaPgoYPlz/X6EEwD2wTr27N+AyQ4uz+xwLYf8ffOGTWZUIX/yvEmz8z314oZ7WnadBfmXcwyftkXx8idj4hyXp75ptKeBOdMTl7wG8eApXlzK2vvRXSb8HT7yW/5RbLffSMHS/+yDtezZv57XWxiTHQSe1Vn4MeQvjpc5q1AV8ifP3/rtIW8CQA5yJQDyL33kFR1WvPzJmLmkyJsAkKOhZYzHOGAt4sFTPNOA3BXwkV88LXuUJAC+MoVqvARAj8kOEs/jqWJ1uDZC/uJ4WfM3qkL+hHPjxg1Py46Z3gSgvmmUp3WPBZA/eySkMZ5rN24rXv5kLFq9rSQBIEfj+Ame2KQcxIOnewWkFb4NH4ni6VifcwmAxtc9Ai0vAagO+QePZ3EwdSB/8bzZK7apQv7ckZa5zCt/Lvj7lQQo+PsycPJmVcifjNUFu0slAI+PDI8xeS3kz+c5XNnwkag1fNV5CUCk0KV/DZshcAmADvIPIo+c/dtd2yB/8bxVBQdUI3/y7/wN+8sE/zY9F6n++5LtPqgK+ZNRsOlgOQnAKE9DS6Ynpt8KyJ+/K8Be+G/4SHD3np6XAEQJyT+CzQ6q8u4XQP5B5BXLvxHk7x+vYPMR1cif/PzGzdvFgT6jjABad5+v2u9LfBrjuXTlpirkT8aWXcfKyJ9bG9LQPNoT03c55P+kW2AefFQhz8BLALS+Fv3xE4Ao0VWCMNmieKSCldnO7Ib8/eNt2X1SNfLnRs+BC8o5A6zgSoAKvi/2CRtVI38y9n53plz5c0d9Y7rHNCAPC0RLKgS6P4CPyuVxCYBO0OfskyJ4ewQh/yDz4h1MC8jff97eQ2dVJX8y5q3cUm4C4E0CeixU3fdlWf5+1cifjKMnL1Yof26BaOOEib7rBKgmvrjd5PYqfFSGZxC1ho+XAGgg/+DzbLZ8jcXJHID8/ecdP31ZVfIvLYDyD+/tAJV8X+KLj+/PX1ON/Mk4d/G6oPz5CwMrrBOgsvhiSWNqwUdleHp/yv1GQP6h4VmdhW0h/8B4F3n3ftUgf27E9pgikASM8rT+eo4qvi9JY4tUJX8yrt+4JUL+j49G1vFl6wSoML6YnQWbuKsA8JGfvEDFj8kWwSMr/53MHsg/MN7tO/dUJ38yMmfkVyh/Tgituim/YuCCnD2qkj953vUbNzz1jb7lz68TUOHtADXFF7v7A/gILYKp4lnSXLUh/8B4pPiLGuVPxqadRwXlr5aKgQcOnVaV/DleE+soUfLnDlI2uEwDIbU1CrKvXwEfQf5U8ax211rIPzBe12GFqpQ/GXfu3vc0TRgjKH9ODqLqBMjw+9JzxDpVyp8cbTqPFS3/kisBZGEgtyZApfGlTdesd+AjyJ8KnsXJ/A3yD5zXZ/QGVcqfG8kjl/qUv5IrBk5fvFmV8ieHuddkv+T/pHfAWO/tALXGF2Ny9jT4CPKnglf85ZwB+QfOSx2/UbXyJ2N53rciV4Mrs2Lgt/uOqVL+5N9dUmf7Lf+SioHm0Z7Y/itVGl9y7rbulPkqfAT5Syv/lPW/MTuZ+5B/4LwhUzerVv5kfH/+apnFYMKXhTNK1wmQ8fel25B81cqf/Lzv0EUByZ/7jjS2jlFtxUCzw2WHjyB/SXkWp3sw5F85XsbsbaqVP8ez9pksejV4ucWCZPp9maSiLpDl8RwZKwKWP79iIGkgpLr44ii41HXw6urwUZB2/0H+/vESbUUGs9N1DfKvHC9r0Q5Vy59wxs9a65f8S64E8G8HyPD7snXXUdXKn4zhWbmVkn9JxUCyRVBssSAFxReLk0mAjyoWP1v3R3SRID3kL55ndboTIf/K82av3K1q+ZNj847v/F4NXup2gAy/L50H53sePHigWvmTMW7W+krLv6RYkD9JgFLii8N9sLzywJC/V/4aUQkAr5+wAfIXObyFf1y7IP/K8xav3adq+ZPjxo2bnpadxge8IEyOFQMnLdyuavmTMX3RhqDI/8nugDEeU8o6dcUXe+H7kH8Z+XP9foQTAPbBOvbs3wD5ixuWNNe7kH9weCvydqla/hxv0PjsSiwIG1GcBMyW1fdl+97TqpY/GfNXbQ2a/LmjScKkiq8EKDO+zID8S/k8iu32GylY+p99sJY9+9fzegtD/r4u/zvckyD/4PDWFu5VvfzJyNuwv9ILwuRSMbDz0ELPgwcPVS1/Mlbm7wqq/PlXAsr0DlBofDGlMndihxY+B/l7eVr2KEkAfGUK1XgJgB7yF7f4z+oouAX5B4e3Yet3qpc/Gdeu/+BpYM6o5D3h0bKoGDhu7nbVy5+MdUUHgi5//pqAkiRA6V0CHUxHyN97Jb8aLwHQ+LpHoOUlANUhf3HD5HRZIP/g8XbuPaZ6+XPja+e8INwTzvAvCZDg+7Lp2xOql78/vSACWyDK3g5QRcXAgl0q7xLIOZxLACKFLv1r2AyBSwB0kL94njllzXbIP3i8Q0e/h/zZMWf55iDdE86gtmLgV4MKPXfv3Ve9/MnYfeB0yOTP8RqY0j1xtmzFxxeyLkul8ueu3nMJQJSQ/CPY7KAq734B5C+S167nN+9B/sHlXb56E/Jnx6Hj54N4T9hHEiDR92X0rK2QPzsOnzgfUvmXqhjYb4Wi44vF4Zqk0jo2Bl4CoPW16I+fAESJrhIE+Xt5xqTsiZB/cHn37j+A/Hmj3ddZQbwsXEESIOH3xb31KOTPLwMdYvlzR0NLpvd2gFLjiylp7a3m0bZfq3ArO5cA6AR9zj4pgrdHEPL3g1fny/Y/NQ/IvQz5B4+XOIiB/J8ao6bmBfmyMD0VAzsMZDy3bt+F/HkLP8Mhf47XyDreY0rJV2x8ie27xKzCrewGUWv4eAmABvL3n9e+77wmkH9wed1HFEL+T40N2w6H4LIwmwRI/H0ZPm0L5M8bd+7eC5v8SxYGJmYptmJgXHJ2tgq3suv9KfcbAfkHxjMmrZ4J+QeX1z+zCPJ/aty+c8/TJH5MCM4MR0teMTC/6DDk/xSvsSU9bPJ/UidgrMc4IE958SU5957Rtvx5+K2CNQA/CnCoXf4NWsX+zJy85hrkH1yeY9ImyL+c0X/Y4hCdGY7wtO4+R5LvS0Ia47l24zY+36d4rb/KDKv8+VsEyxQLUkSXQKY9/BbEgS6BNWvE9l3YHPIPPm/E9C2Qfzm8+SuLQnhZeISnTfe5Yf++DJy8GZ9vOby4HhPDLn/utlC5ZYPlHl8crmz4DfIPKs9sd82A/IPPGzt3G+RfDu/Q0dMhviwc/oqB2e6D+HzL4XVMmiaB/HkVA63jnjQQUkJ8SWUeJDg2Pg+/Qf5B4bXoMkNntTPXIf/g86Yt+Rbyr4Bn7p0V0jPDBuZMT9tei8PyfYlPYzyXrtzE51sOr/egBZLJnzuaJk5WVMXAeLvbCL9B/kHhmZ2FDSHr0PDmrd4D+VfAGztzTRjODMNTMdA+YSM+3wp4KaOXSyp/jtfQnOGJ7b9SEfHF4nStgd8g/6DwrA7XN5B1aHjL1x2A/Cvg7dh7Iixnhj6vBATh+7Isfz8+3wp4QyfmSC5/jtHImskmAfKOLyZnwUPLYOZn8BvkXymezZavsdpdVyHr0PCe3hZGQzDff/isdyue1HIg7XK/7DguLHJ4nAQsCcn3Jb74+P7CNUk/31z3HmqTiTEz1lEhf26BaJOE8YqoGGhxuKIhfz92/0H+ZXnxaa73IOvQ8TbuPEHdmdyU+Yy3SQsNckgbszKMcsgofSUgSN+XpLFFkn6+pNxuy04TqL2SMGVBISXyf7JAtNTCQLnGF4frG5X7jSv9L7pIkB7yL82zOhg7ZB063q4DZ6i7jDt21jrPsrU7qZBDrntvWOVArgRE914a1O/Lwty9kn6+ZA59JQBSvr65KzZTJP8nLaVJxcAK6wTIIb44Ci41nTs3QsXy14hKAHj9hA2Qf+lhtbu2Qdah4x0+cZG6e7gjJ6/xjJq6lgo5XL52q1jKGWGVA/l9pE5AsL4vx05dkvTzHZ6VK5gASP39W563kzL5+6gTIKP4YnK4/6lS+XP9foQTAPbBOvbs3wD5Pxnxgzb+ArIOLY9cnqVtAVfa2FWeLqlzqLky0cU+J+xyqG8c6WldkgQE/vn2GVUo+fzF9ZxaYQJAw+e7tnAfhfJ/kgQ0ip9Q8e0AyuOL2e4aoEL5R7HdfiMFS/+zD9ayZ/96Xm9h1cufDLKIBLIOLe/8xcvUrd5OTl/mrcV/7/59KpKTWUs3SiKH+sZ0T9se8yv1+c5YskXS+Tt74Zr3vZWXANBy5al08yea5P8kCWjacYosKwYaU1ZvVdltbS17lCQAvjKFarwEQA/58xIAJzMbsg4dz5Ka57lx4wZ1W7d6D17oDYr7Dp6kIjk5ePSspAvCKlMx8Nt9xySdP24NRYuvxlO7dXDnvpMUy593JcA6/kkDIbnEq6ScR62sA/9HJfLXsT7nEgCNr3sEWl4CUB3yfzLI9j+znbkMWYeOl5iWR+W+7S6ps73BcWXeNipe36NHHk90tyzJ5FCyMNDPz7fbkHzJ52/YpNzHCUDH8dTWDTh49Bzl8uetCeiQ5TEmr5VVvIrtt9ikAvlzDucSgEihS/8aNkPgEgAd5F96kMUjkHVoed2H5lNZtMXaZ4o3QI6ZnkvN6xs5ZY2kcqiwToDA5ztp/kbJ5y+m+2Tv62+eOI7aokGnzl6Rgfz5XQTHe2L6rZBNvDIlr56rcL9xV++5BCBKSP4RbHZQlXe/APJ/evW/w9ULsg4tr9+odVRWbGvfbbw3SHZ3fkPN62O2HpJcDj6TgKc+3y3fHpF0/k6feyLWZh3GUlsx8PLVWzKR/5OW0g0tmR5jUrZM4tX6Uz/yeKoo2G8GXgKg9bXoj58ARImuEqSyokFmh2s5ZB1ann28i8pyra06Pu7P3rzDaG81Phpe381btz0NzSMll0MD85jybwc89fl2Hvz49o6Un2/2+t1Pmt0kZFJbLphUnZSP/HkVAztM8Bh9bRGkJF7FpzAvK9hvXAKgE/Q5+6QI3h5ByL/c+/+eH5e6/w9Zh4SXPmMLlbXam1jTS4IluTxLy+vrNXA2FXIo0zugnM933JwiyeU6aHx2yfttbEmnuldAA9MIGcn/yQLRxgkTxRcLkjBemR3uVgr2m0HUGj5eAqCB/AXO/u0Fr0HWoedNmL+dOvnfuHHTU9/4JFiu33iAmtc3d1khNXIouRJQwee7bc8pyeXapuukkvdLrp7Q3CioZWKmzOQ/qtTCQFNKPt3xysFkKthven/K/UZA/sKD9JKGrEPPm7HsW6rkT45Ll6+WCpaT5rqoeX0HDp+iSg7eKwE95pf5fDsPYQK6dRLM+Tt68kKp99vQNJLqLoEx3SfIUP5Pdgc06zjV95UACeOVyeneqXq/BSp+tdVSLv7CTIGsQ88jNeJpkj/599VrN0sFN1ITgKbXZ+o9lSo5lFcxcNy8bZLLdXHO9qeKGo2gukVwQr+pMpW/TCoGphY8MqVtqQG/Qf4iFgAWfAdZh56X7TpIlVzJz89ful4qsJF2vGQfPi2vb/w3BdTJ4emKgZu+PSG5XG3DFpR5v7TKnxxf27+RsfxLVwwsKRZEWbyypDG14DfIX3AY7at/AVmHh1ew+QhV8ifj5JnLZQLbiTOXqHl923Yfp1IO3BbBrwYVeu7euy+pXK/fuOFpljC6zPt95CuTk/DzTRq5VOby5yUBiZOf3A6gKl65B0D+kL8gL7bPkhaQdXh4W3afpEr+ZBw6dr5MUCPNWmh5fffuP/AWtaFRDmRh4PApbsnluvXbQ+W+Pn/XJYTz8x08frUC5P8kCSC7A8wp+XTFK7trLeQP+Qvy4pJWDYWsw8Pbe+gsVfInY8/B02UC2rhZ66l5fWTYM1ZQK4f1G6W/rTN13vpyX9/dew+olD8ZGdPzFCL/J0fTxIme2P4rqYlXJidzg2zxhvwh/wp5ccnZ2ZB1eHjHT1+mSv4VXWLv5phHzesjY3XBbirlQDoo3rp9V3K5fm2fVe7rIwV3aJQ/GVnz3AqS/5OKgY0smWwSQEe86pCy/hXIH/KvkGccsOYUZB0e3sUrN6mSPxlF28u2ZiViu3//ARWvjwwybw3M9MmBtFGWWq4XLl7x7vkv7/Xd+uEulfInY/ayTQqT//CSXSKkd4Dp6YWBEsUrc+q6+mqTv+jdf2qXf4v2tpcg6/Dxnj4jo0Gu64oOlBvYSEtemmrJd0qZTZ0cct17JJdrQdHeCl/f9Zu3qZQ/GUvX7FCc/J8sEBVZJyAM8SouaVWKivzGlf4XXSRIr1b5k6N9r3m1IOvw8BLSGOrk//jy+p5yg9uytTupqiU/Y3ERVXIgl3qv3bgtuVzHzMyv8D1dvf4DlfInI9e9V5Hy57eU9i4MTF0nabwyJWcvUpH8NaISAF4/YYNa5U/+bXYUdICsw8PrOqyQOvlXfCY2yjNo7HKqasnvP/w9VXLoM2QRFXK19J1e4Wu8VM4tJ1q+f4+7PSpT/vzKkc2+mlq2TkAY45VpwOoDKpE/1+9HOAFgH6xjz/4NapU/+bnZ7h4HWYeH12f0BurkT8a8lVvKDW7m3llU1ZInW9rbdJlIjRyW5+2UXK5nL1wTWBsx2lvkiUb5k7F9zwlFy5+fBDRJzKo4CQhxvIpLyXnYtF3Xnylc/lFst99IwdL/7IO17Nm/ntdbWHXy95YAdjAbIOvw8FLHb6SyP/vMJUXlBjfSIOjsuYtUlZMdPD6bCjkQ6Z67KL1cV63fJfg6SYJAo/wfX9E5q3j5P50ElCkbHKZ4ZU7N+4eC/aZlj5IEwFemUI2XAOjVKn9vC2AncwOyDg9v8JRNVPZnf7Idq2xwYzbvo6qc7Iq126iQQ2LSLCrOrJ1jVgq+ztO81s60JZ+k2qQa5F/6dsA0SSoGxjvd7RTqNx3rcy4B0Pi6R6DlJQDV1Sp/Msj+UMg6fLyR0wup7M8+Zua6CoPbjMUbqKolf/zUWe+VCamD+ZT50i/ofPjwkafFV+MFXydX0pnGK08XL99QjfxLXQlImOTdIhjOeGVxMkMV6DfO4VwCECl06V/DZghcAqBTs/y9l/+dhR9D1uHjjZuzgcr+7COycisMbrbhS6irJW/ulSV5MN914JTkZ9Z7D53x+TqPnrxIpfzJIAWU1CT/J0lAhrdiYJxtVdjilcXOLFaY37ir91wCECUk/wg2O6jKu1+gavmTYXG64yDr8PGmLdpMZX92R8bSCoMbOcP0p59MOGQzaupqSYM5mZMH7PuRUq4zy2yLLHt8d+wclfLnFnWStRRqkj+/pXTThAnhqxiYyuxQmN8MvARA62vRHz8BiBJdJUjhRYOsDsYOWYePN3fVdir7sycNXyAY3I6fvkRVOVnh7WOhD+ZpY1dRcVm9m2Ouz/e7c+9RKuXP8Zp3GK06+fMrBjaOH+dtIBTqeGVyFlz7kcdTRUF+4xIAnaDP2SdF8PYIQv4lCYB7JmQdPt6KvF1U9mfvPWiOYHAjdfhpKid789YdT0NLhmTBPMe1R3L5kwp/wnPw+P2SLoG0yp88v13XcaqUP79iYPNO033XCQhCvIodWvicgvxmELWGj5cAaCD/pxIAJ1MIWYeP5956lDr5k6Nr6izB4DZy8hrqysn6PvsNTTAnl6wvXLom+WX19RsPiHq/m3YcpFb+hGPtM1m18udXDGzSIUt8EhBgvEpILXxTQX7T+1PuNwLyLzcBOANZh4+3fe9p6uRPjkTbNMHgZu03g7pystMXbZAkmHdMmkXFPfXhWbmi3u+GrfuplT85uqTMVLX8S20R7Di1bJ2AIMYri9PdWHW9cAIVv9Inp/PQwmqQdXh5B4+ep07+5N9WgVKy3FlveTXvpbwMvnPfSUmC+YRv8qm4p9626yRR75e2Og5P8/oOnqd6+T/5OxsjfDugsvHKwXRTlfwrM5Q+OZaB7j9C1uHlnT57lTr5k5/H9JjiM5gV7ThCVUW5u/ceeJomjAl7MN+4/aDk8icr+8W+3w3bDlErf/JvX4WM1CJ/fhJAKgaWaSAUjHjlcI+G/CF/74h3FH4GWYeXd+XaD9TJn4xWnSb4VfiGln3l/YYtDmswb5Yw2nPt2nXJ76nPWb5Z9Pt1b/6OWvmTn6dPWQv5+7oSELx4tQLyh/wf3/+3u2Ih6/Dy7t1/QJ38yRA+k3589Bg4n7qKcmWbGIU2mJPtkjQsqOueNl/0+11XtJ9a+ZMxcY4L8q8gCSBrAozJa4MWr0xO907IH/J/fAvAwfSArMPHSxzEUCl/rhiLr4DUJH6M587de1QVlSnbTCa0wXxh9kbJ5X+j1PY/3+83172XWvmTMWvpRshfqGxwhwkeY1J2kOLV+lOQP+TvHWZHwRDIOny87iMKqQu+ZNy+c090cOPvKafhTNhbC7/j+LAF88PHvpd8Qd2T7X/i3i/pFkir/MlYnLMd8hesGJjuad5xclAqBsYl5d2pWf+LZyB/lcufPC8uOXs6ZB0+Xv/MIuqCLxlkdb/YYDRzkZu6ojIpo5aFJZjH9ZhExfsdOjHHr/e7bO1OauVPxuqCPZC/z4qB6Z7GCeM8pgGVrxjYvH3nX6pB/qJ3/6lR/uT5puSclZB1+HiOSZuoC75knL94XXQw6jd0PnVFZcgZZDiCeeb0fMnf76NHjzytOk/w6/0uWr2NWvmT4dp8EPL3yRvhvR1AFgaa/C0b/FS8apM45nWF+40r/S+6SJBebfInnLjk1UWQdfh4I6ZvoS74knHyzGXRwahFYmYxk66iMvsOnghLMC/afljy97vnu9N+y2buis3Uyp+MrbuOQf6ieBm+6wSIiFcx3Wf/R+Hy14hKAHj9hA1qkz85TMlrDkLW4eONnbuNuuBLxqFj5/0KRkdOnKdG/hyvVcfMkAbfRtZMb+taqd9v1px1fsuGLLKjVf5kVNzSGPIvy3ucBDTtOMVjTl0fULyypK77TMHy5/r9CCcA7IN17Nm/QW3yJ4cxJfcSZB0+3rQl31IXfMnYffC0X8Foed5OquRPjtT0RSENvj0HLqDi/Sb0m+q3bKYtLKRW/mQcO3UR8veL9zgJ+LLzzIAqBsY7mBYKlX8U2+03UrD0P/tgLXv2r+f1FlaN/Gs1a/Ss2VHwELIOH2/e6j3UBV8ytu0+7lcwGsi2wqVpa9nCVZtCGnxnL9sk+fs9fuqsp77Rf9lkzXVTK//y16BA/r55GSV1AsqsCfAZr9yJCvSblj1KEgBfmUI1XgKgV5P8yb/NttwXIOvw8pavO0Bd8CWjcNthv4JRdLcs6vaVl38WGbzgS+oNSP1+F6/eFJBsxs1aT638vXUNbt2B/APiZXgaWoqTgK+mPWkgJCJeWRxMssL8pmN9ziUAGl/3CLS8BKC62uRPfm5Kc70EWYeXl7fhEHXBl4z8Dfv9Dkanzl6hbmtZm3Kb41Q++LbsNMG7+l7q99t/6PyAZJMxPY9a+XO1HB4XooL8/ec9TgK8twPEVgx0uIcoyG+cw7kEIFLo0r+GzRC4BECnRvmzfQBehazDyyvYeIC64EtG9vrdfgcjsnebtq1l5NZEKIIvaVYjtfwvXb7qaWJND0g2I7JyqZU/N5p1GAP5B8wjSYD4ioEWB5OuEL9xV++5BCBKSP4RbHZQlXe/QJXy91YBtBe8BlmHl7dpxyEqg++inG1+ByNSjIa2rWUr83eFJPiuWrdL8mRnfdHegGUzeHw21fInz2vbeRzkXyneCE8D0+OKgXG2VYLxymx3j1OI3wy8BEDra9EfPwGIEl0lSKFFgyxO5m+QdXh5uw+coDL4zljk9jsYxXSfTN3WshNnLoUk+J45d1XyZCewjnmP3++A9MVUy58839w7C/KvNO9xEtCsY5b3dkBFMcniYCYrxG9cAqAT9Dn7pAjeHkFVy//xLYCCdyDr8PKOHP+eyuA7cXZeQMHoaTHScJlZeB2A/8HX2Guq5PJ/8OChd+FloHLgqjfSKn/C6ZQ8A/IPUsVAcjuALAysqE6AxemepRC/GUSt4eMlABrIn00AnMx/Ievw8s5fuExl8M2YmhNQMMp176FudXnF6wACC76jp+VJfqXjwJGzlZJD70FzqJY/OchrhPyDVzGQLAxs0WVW+XUC7Mx8hfhN70+53wjI/8mwOgs/hqzDx7Ok5hWfyT2gMvgOm7AyoGA0bFIudavLl+d9G9TgS+rUS32bY/qiDZWSw9f2WVTLnxzkNgXkH9yKgd4tgt46AeueilHuZarqhROo+JU8OWaH+3PIOny8ToMZaoOvM2NZQMGIrAOgbXV52XoAgQffBuYMb6dEqW9zdEz+plJy6DRgOtXyJ/8ePikH8g9BxcCGlrHeLYL8JMDsZFarRv6VGUqeHLOzsCFkHT5er/QN1AbfAd52uoEFo0PHzlC1wIxs12/VeWJQgm+nlNmSy//cxevsHvnA5ZBom0m1/MnPx3+zHvIPUcVALgngbgeYne51kL+K5e+9BeBwN4esw8dLHltEbfDtO3RRwMFoac5m6haY2TNWBCX4Tp7PSL7GYdnanZWWg6XvdKrlH4zbHJD/aJ9JAG9hYCHkr2L5excB2pkmkHX4eAMnb6I2+HZzzAs4GKVlLqWvrsHqbUEJvlt3H5d8jUO/YYsrLYeYHlOolj8ZC7K3QtYhrxg49vHCwOQ8N+SvYvk/XgToqgtZh483auZWaoNvYtKsgINRm85jqVtg9u2+Y5UOvo3jx3hu37knqfxJjXzShriycmjTZSLV8ieDFFuCrMNRMXCMp0niuCLIX8Xy9xYCSmNqQdbh402Yv53a4Ev2ulcmGJGFdzTdY75+/YanecLoSgXLXoMXSr7AcV3R/qDIoXniOKrl//i9HoCsw1QxsF7MsCLIX8Xy9yYAKes+gqzDx5ux7Ftqg6+4JjoVB6PleTupu8fcZ/DcSgXLb5ZulHx3Q5pgbwPxcmhkyaRa/mRs2nkUsg4Tr1bbFEYN8he9+09t8ifPi+k99xPIOny8hbl7qQ2+TRPGVCoYOTJWUHePecZCd6WC5bbdhyWV/737D7xn7sGSwwOB30XDVs7dB05D1mHi1foyab3C/caV/hddJEivJvmT57ftNbMmZB0+XrbrIJXB90kr1sCDkdh2ueF8vzv3nQw4WDZLGO25dv26pLsbKj4jDkwOZD0DrfIn4/CJ85B1mHifftl/jcLlrxGVAPD6CRvUJH/Caf/1tH9B1uHjFWw+QmXwvfXD3aAEo4NHz1J1mfnuvfsiFtCV/377U1A7f9TUvKDK4emCRrRVcPz+/FXIOky8D1skr1Cw/Ll+P8IJAPtgHXv2b1CT/MnR5utJb0HW4eNt2X2SyuB78crNoASjeSu3UHePuZtjbkDBcu7yQkllSK6mlF2XUTk5XLh8g1r5k0ESFMg6PLyPmvdbpFD5R7HdfiMFS/+zD9ayZ/96Xm9hVcifHO06jX8Dsg4fb++hs1QG31NnrwQlGJH96rTdY86a6w4oWO45cFxSGe4+eDrocjh97gq18ifj/v0HkHWYeB807j1PgX7TskdJAuArU6jGSwD0apI/+XeMbdWvIOvw8Y6fvkxl8P3u2LmgBCOykPDuvQdUXWYu3HbY72DZqmOm5DKcOMcVdDkcPXmRWvlzo0n8GMg6DLz3G/eeqTC/6VifcwmAxtc9Ai0vAaiuNvmTn0fb8rWQdfh45FI7jcF314FTQQtG2/eeoOoy89XrP/i9wDF11BLJZRjXc2rQ5UDWaNAs/8fbUSdC1mHg/bd+tzEK8hvncC4BiBS69K9hMwQuAdCpUf68aoC3IOvw8G79cIfK4PtktXnlg9EUCmrnPz3Mfab7FSxX5H0r6efx5IpMcOVAEj2a5U+eZ+yZBVmHgfdu7Q5pCvEbd/WeSwCihOQfwWYHVXn3C1Qrf28CYGeOQ9ah5yU43dQG34JNB4MWjLjueTSdaY7IyvUrWJ78/rKkn8e0hYUhkUPhlv1Uy588v6NtOmQdBt5bH7XrpRC/GXgJgNbXoj9+AhAlukqQgosGWe2ubZB16HmdBuVTG3yz1+8KWjBqYM7wXLl2k6pkZ9X6XaKDZfvukyX/PKz9podEDvmFu6mWP+H0SPsGsg4D7/V/NbUoxG9cAqAT9Dn7pAjeHkHVy9+bADiYHMg69Lyew/OpDb5zlhUGNRitXr+TqmSHLH4TGyyHTsyR9PMgPRVCJYec9Tuolj85koYvgKzDwPvDm7WaKcRvBlFr+HgJgAby5ycArm8g69DzkjLWUxt8p8xbH9RgNHjccqqSHbKnvkXH8aKCZa57j6Sfx7QFrpDJYfmaLVTLnxyDxi6DrMPAe/lP//qnQvym96fcbwTk/1QC4GRGQdah56VNcFEbfMdMzw1qMGrbeSx1yU7/YYtFBUtSjU7KzyOh75SQyWHhqk1Uy5/8O3NGPmQdal5c+qNfv/tuNVX1wglU/EqfnGJZJUHWoeeNnF5IbfAdNmFl0IPRvoMnqHq/T1/lKO/9xvaYIunn8d2RU576xtDJYcGqLVTLn/x86oJCyDrEvHqxw6+pSv6VGUqfHKvTnQhZh543aeF2aoOvY/TS4MsmeytV79e9aa/PYDk8K1fSz+ObJUxI5fDNsk1Uy58MUk4asg4tr067oSchf8jfO8xprmaQdeh5s1fupjb42oYvDnowEioLLMX7PXvuYsnZdUXBcg2zV9LPo2vqrJDKYUrx2TXN8idjed63kHWIeZ+1TdsF+UP+bAJQ+DZkHXrekrz91Abf7mnzgh6MSElX0o2Ppvdr7jVZMFieu3hdstd3+vvzxQnKiJDKYfw3BVTLn4y8Dfsh6xDzPm4xIAfyh/y9wzKY+RlkHXpeLvMdtcE3wTYzJMFo665jVL1fssWvovdk7DVV0te3LHdLyOVA2gvTLH8yirYfhqxDzHu/0dfTIH/I3zv+YusbYU5Z8wNkHVoes+0YtcE3pvvkkAQj0tCGpve7PG9nhe8rfcpaSV9f0silIZfDkAmrqZY/GTv3nYSsQ8x79zPTcMgf8i/hGZPW7IOsQ8vbvvc0tcH38R754AcjcmWBpvdLmuFU9N7IpWepXh/pEfG4C15o5eDIWEG1/Mko25kS8g8276/vNempFvmL3v2nVvkTTlxydjZkHVrewaPnqQ2+DS0ZIQlGpAvfhcs3qHm/pN9843JES17n+UvXJXt97s3fhUUOtuFLqJY/GafPXoGsQ8x79fV/t1GB37jS/6KLBOnVKH9yGJOyx0HWoeWdPnuVyuBLFuqFMhjluPZQ9X67OeaWeY2m3tMkfX1CaxOC+Xn0HLiAavmTcfnaLcg6hLw67YY//N///ev/qED+GlEJAK+fsEGN8vdeAUha2QeyDi3vyrUfqAy+167/ENJgNGhcNlXvd+ysdYL3/8P9+h4U/7dlpwlhkUPnlDlUy5+MO3fvQ9Yh5H0RPfCsCuTP9fsRTgDYB+vYs3+DGuVP/m1JWdcYsg4t7979B1QG37MXroU0GLUqlhupxU/L+11buK/MayQ/k+r1bd97ImxyiO83g2r5c6ORJROyDhHv09apOxUu/yi222+kYOl/9sFa9uxfz+strCr5k58npBa+CVmHjpc4iKH2zIt0nwt1MNp/+Cw17/f46Uvl7v+X6vWVd0UiVJ8Hv9QxrfIno5X3ighkHQreR1/2X6Vgv2nZoyQB8JUpVOMlAHo1yp/8//G2fL3V7noEWYeG131EIbVnXvsPfx/yYPTN0o3UvF9yNaJ54riS1xbXa6qkn0dMsZTDJYfWnSdSL38y4npNgaxDxHuvfpcxCvWbjvU5lwBofN0j0PISgOpqlX9JRUCn6zvIOjS8/plF1J55lb0EHfxg1M0+iyrZ9By04En9/0k5kn0eB4+eC6scmiaMpV7+5Hkd+k+FrEPEe/P91t0U6DfO4VwCECl06V/DZghcAqBTu/zJsNrdCyHr0PAckzZRe+a1YdvhkAejhqaRnvMXLlMjG1KgiHt9K9ZulezzmL5oQ1jl0MA8inr5k+d/bZ8FWYeI9+L//LW+wvzGXb3nEoAoIflHsNlBVd79AtXL35sAlNcWGPIPCm/E9C3Unnnll9ReD20wyivcTY1sHr/nx6/v0NHTkn0eiUmzwi6HS5evUi1/wuk/dD5kHQJendhh137k8VRRmN8MvARA62vRHz8BiBJdJUgFRYOsdlcjyDo0vDFztlJ75rVq3a6wBKORWdnUyIYsfCSvKbrrOMk+jzPnrnoLEIVbDqQrIs3yJ0da5lLIPwS8Wq2d2xXoNy4B0An6nH1SBG+PIOTPG/GOwlch69DwJs3bRO1l14XZW8MSjIy9plAjG8JoGj/KKxqpPo9Fq7dJIofjp85SLX9ykGQR8g8+78Mmfecr0G8GUWv4eAmABvIvO2w2z4+tTtctyD/4vJlLt1B72XXa/IKwBSNS5pUW2XRJmelZvHqTZJ8HqconhRy+O3qGavmTf2fNc0P+IeD98zPrIAX6Te9Pud8IyL/iYXW4NkL+wectWL2D2suu42auCVswIt34aJHNrn3HPOcuXJLk87h6/Ydy+i+ERw6Hjp+jWv7k53OWb4b8Q8B77e36ZtX6LVDxq0X+j9cBMBMg/+Dzstftpvay68isVWELRimjl1MnGyl4pD+CVHLYe+gM9fO3dM0OyD/YvLj0R8/9/JW31ew3yN/nFQAmHvIPPq9g4wFq5TVo7LKwBSNSgOfBg4eqlj8ZJBGSSg6k7gPt87eG2Qv5B5n3efthJyB/yF9wWJLz3oT8g8/7dv9pauU1YOSisAajXQdOqVr+t+/c8xbkkUoORTuOUD9/hVsPQf5B5n3SPGkF5A/5C/JqNWv0rDFl7U3IP7i8wycuUiuvfkMXhTUYTVtYqFr5l5abNHIo2HSQ+vkT1yAJ8veH985n8QMhf8jfJy8uaXU+5B9c3tkL16mV19fOeWENRnJoSRtK3rBJuZLKIde9h/r5O3DkLOQfZN4rr7/fGvKH/H3yjLaVaZB/cHk3bt6hVl7C1eiCH4wamDM8167/oEr5P3z4yNOq03hJ5eBrJwYN83fyzGXIP4i8Ou1HXOUqAEL+kL8gr33f+fUh/+Dx4tMYbwc6WuVFuuGFO7itKzqgOvmTsWPvCcnlsCB7K/Xzd/HKTcg/iLxarR1utcpf9O4/yP8xr61tSQ2z0/UQ8g8Or9OQQqrlRVrEhju4jcjKVZ38yfMypuVILodZSzdSP38/3L4H+QeRR1oAq9BvXOl/0UWC9GqXP8czO5ntkH9weD3TN1AtrybxY8Ie3Np1m6Q6+ZPnx3w9QXI5TJ7PyGL+yK0iyD84vNffaZigQvlrRCUAvH7CBsifqwfgHg35B4eXPLaIWnk9KP5ZxQ1pQhvc9h44rir579p/jAo5jJ21Thbz16LjeMg/CLw6MSPvvfTSK++oTP5cvx/hBIB9sI49+zdA/mw9gDTmS8g/OLyBkzdRK6+bt+5IFtxmL2VUI3/CmTx3HRVyGDlljSzmL6bHFMg/CLxarey7VSb/KLbbb6Rg6X/2wVr27F/P6y2savmTYRqS/1Or3fUI8q88L33mVmrldfHyDcmCW+9Bc1Qjf3Ik9JtKhRwGjc+Wxfx1sM2E/IPA+2+DztNVdGVbyx4lCYCvTKEaLwHQQ/78ssC8xkCQf8C8CfO3Uyuvk99fliy4Nbake27fuasK+R85fsZT30iHHEgZYjnMX9fUmZB/EHivv1O7o0rkr2N9ziUAGl/3CLS8BKA65P9UAuBkkiD/yvNmLPuWWnl9d+ycpMFt665jipc/Oeau2ECNHEjlRznMX5/BcyH/SvLqRA+68vrrb/5GBfLnHM4lAJFCl/41bIbAJQA6yL/siHcUvAP5V563MHcvtfIidfmlDG4T57gUL3/y796DFlAjB3JmLYf5s49aDPlXkvdR875rVSB/7uo9lwBECck/gs0OqvLuF0D+5Yymc+dGmJ2ui5B/5XjZroPUymvzzqOSBrcE20zFy//q9VueRpZMauTQof80WczfsAkrIf9K8t75NHaQCvxm4CUAWl+L/vgJQJToKkEqLRpkcbpnQf6V4xVsPkKtvEhjGCmDG9mCeOHyDcXKn/zcv9a2oZeDuVeWLOZvzIw1kH9leDHDHr3w6z/UVYHfuARAJ+hz9kkRvD2CkL+vBMDBtIH8K8fbvOsEtfLKce2RPLiR16BU+ZNhz1hBlRzadR0ni/mbuaQI8q8E77PoQXtV4jeDqDV8vARAA/mLG0b76l9A/pXjbdt9lFp5LcndLnlwGzQuW7Hyv3P3vqdpwliq5NCyY6Ys5m9xznbIvxK8/zboPlklftP7U+43AvL3j2dKzt0G+QfO2//dKWrlNXORW/Lg1qrzxHKbJSmhV8CGbYepk0OT+ExZzN/qgj2QfyV4f/5HPQv89tQagB8FONTcKCguaUUS5B8478Tpc9TKa+LsPCqCG+n/rjT5k0GaHtEmB7LuQmx3Sinnz7X5IOQfIO+LmBHnatR4+Rn4LQhD7V0C23Qe9xfIP3DexUtXqJVXxtTVVAS32cs2KU7+Dx8+EtlpMfyyuX3nHvXzt3X3ccg/QN4HjXvNht8g/6DxrHb3Zsjff541dS3V8hoyfgUVwa3HwPmKkn/5NRbokc3V6z9QP3/7Dn0P+QfIe+3t+mb4DfIPGs/qYLpB/v7zOg3Kp1pe9lFLqAhuZJ/8zZu3FdUimBQ5olU25y5ep37+jp++BPkHwKvTfsSZH3k8VeA3yD9ovPgU5mXI339en1GFVMsracQSaoJb/oY9ipE/GcZeU6mVzYkzl6ifv/OXrkP+AfDeb9x7JvwG+QedZ3UwGyB//3ip4zdSLa+eAZWoDU1wGzFplWLkf+TEBaplQ3pA0L71suJW1ZC/EO9Pb9aJg98g/6DzLI7CTpC/f7whUzdTLa9OKbOpCW6x3ScoQv5kfLN0I9Wy2X3wNPV1F8hOBbJjAfIXz6vdfvApocv/apS/6N1/kL8wLzGt6NeQv3+8jNnbqJaXpe90qoLboaNnZC//ihMremRDVtjLoe5C88RxkL8fvJoNe0+H356In637I7pIkB7y99kiuADyF8/LWrSDanm165ZFVXBbtnan7OV//uJ16s9cC7cdlkXdhXZfZ0H+fvB+/5dP2kH+JfLXiEoAeP2EDZC/8LA4XNGQv3je7JW7qZZX6TMs6YNbyujlspY/GUvX7KBeNuuK9sui7kJ8vxmQv0je520H74f8S+TP9fsRTgDYB+vYs38D5C88TLYtOqvddRXyF8dbkrefank1MGdQFdxIQvLgwUPZyp+MPkMWUS+b1QW7ZVF3oZt9DuQvkvevzxOGQP5en0ex3X4jBUv/sw/Wsmf/el5vYchf6CqA050B+Yvj5TLfUSsvUg2OxuBGCujIVf43bt721jSgXTbkKoUcii71HjQX8hfBqxs78naN51/6CGvavD7X8hMAX5lCNV4CoIf8fY/4VPdfIX9xPGbbMWrldeXaLSqD27SFhbKUPxlrC/fJQjZzV2yWRdGllPRFkL+I53/YzLYc8vdeya/GSwA0vu4RaHkJQHXIXzzPPGDNNsjfN2/73tPUyuv781epDG6dU+bIUv5kODJXykI2k+eul0XRJa5UNeQvfPA7/6lU/pzDuQQgUujSv4bNELgEQAf5+8eL67/sK8jf9/MPHj1PrbyOnrxAZXAj6xKuVVCrnmb53733wNM8cawsZDNuxhpZFF3KmJoD+fs4Pm835Ai391+lPuKu3nMJQJSQ/CPY7KAq734B5O8nr2Fsn1+bktfcgvyFj9Nnr1Irr72HzlAb3NYVHZCV/Mko2n5YNrJJz8qWRdElcqUC8hc+/l3nq3SV+8jASwC0vhb98ROAKNFVgiD/Mjxjcs5UyF/4uHLtB2rlta1Uu1W6gtuIrFxZyZ88b9iElbKRzeBxy2VRcXHBqi2Qv8BRJyb93rO/+kNtlfuISwB0gj5nnxTB2yMI+VeCZ3Tkvw35Cx/37j+gVl6FWw9RG9xIgSI5yZ8wWncaIxvZkC6Qcqi4uGr9Lshf4PikuS0bPvL+7+piC/5EsGsAIP8g8MxO9zrIv/wjcRBDtbzyNuynOriRNQpykD95/uad38lKNskjl8qi4uL6jQcgf8HKf5/GwEcid+/xEgDIP0g8q9NVF/Iv/+g+nKFaXivyvqU6uC3I3ioL+RPO2Bm5spINKVYkh4qLm3cehfwrOvtv49wEH/nBC1T8kH/FPJvN82Org9kP+Zfl9Umne6vV7KUM1cGSFIGRg/zJEddjoqxk080xTxbllknXQsi/fN5f32/aBz5Ci2DJefF2txHyL8sbMLaAanlNnruO6mDZxJruuXzlKvXy33fwhOxkk5g0Sxbllo+cuAD5l8P7PNp5pGb9L56BjyB/yXnRtnyt2cmch/xL8wZPcuOydSV5zKa91K9Wn7HQLTvZmHpPk0W55bMXrkH+5fDe/TR2CHwE+VPDszrd/SH/0rxRMxiq5TVi0krqg+WYGWuoX63eJWW27GTD32VBc8XFazduQ/5P8T5vO/jii7/57b/hI8ifni6BQ/J/WizB25D/E96keZuollda5jLqg2WCbQbV8j9/6ZqngVl+smnRcbwsyi3fv/8A8n+K936djlnwEeRPHc/qYDIh/ye8udm7qZZXyqhl1AdLItcLl29Qu2Bted5OWcqmkTVTNr0WmsSPgfxZRp32w27/6qU/NIKPIH/6ugSmMC9bUwvuQf6PecvXHaB6q1XfoYtkESxzXHuoXbDWb9hi2crmwYOHsii33KbrJMifPWrW7zIbPvKbWQWTEyaeMTl7AuT/mJdfdJjqrVbdHHNlESwHjcumcv5u3rrjPZOWq2xu/XBXFuWWLX2nQ/7FR932Q2798uU/NYKPxIufrfsjukiQHvKvHK9lh9F/NiavvYMugYxn484TVG+1SrDNlEWwbNV5oufRo0fUzd+6ov2yls3lq7dkUW65S+oc1cufHP9t0HkafOSX/DWiEgBeP2ED5F95XpxtVQa6BDKeXQfOUL3VKrbHFNkEywNHzlI3f2ljV8laNt+fvyqLXgt9Bi9Uvfzrth98/ac/fakWfCRa/ly/H+EEgH2wjj37N0D+lee1/GrE76yOgltqbxR0+MRFqrdateo0QTbBcvayTVTNH2ny1DxxnKxlc+zURVn0WhgwcpGq5U+O/9TrNB4+Ei3/KLbbb6Rg6X/2wVr27F/P6y0M+VeSZ3W609TeJfDshetUb7VqXGZ1Nb3BssfA+VTNn7ga9XTLZv/h72XRa2HQ2OWqln/d9sMu13j+5zXhI1E8LXuUJAC+MoVqvARAD/kHh5fg2Pi81c5cV3OjoBs371Ar/4r3V9MZLBtZMkstWpN6/kZNzZO9bDbt+E4WvRZGTclWrfzJz9+r23k0fCSKp2N9ziUAGl/3CLS8BKA65B9cntXpHqBW+cenMRUuXKPhsuuNm/KrsFa47TAV80c+1uhuWbKXjXvTXlk0Wpo4O0+18v+83YgL+mdffA8+ErWGrzovAYgUuvSvYTMELgHQQf7B5yXaigxWu+ucGhsFdR5WRHWRlfOXrssuWGZMz6di/vYeOqMI2axldlEvf3LMXOxWpfzJ///Pz6yD4CNRu/f0vAQgSkj+EWx2UJV3vwDyDxHP4nTHqbFLYJ+MLVQXWTlx5pLsguWXHcd6Og2Y4emUzDuK/901dY6nq32u/0fx8wLhxfWaqgjZrMrfTr38yb8Dq7Yof/nXbjP4YFSNGr+Fj3zyDLwEQOtr0R8/AYgSXSUIkx0Qr+ncuRFmJ7NdbY2C7JN2UF1k5eDRsyivqnLekpzN1Muf/Dx/w35Vfr6vv9ukA3wkisclADpBn7NPiuDtEYT8w8CLdzL/VVuXwGEzd1FdZGXnvpOQocp5i3K2US9/Mop2HFHd51vry5Q8+EM0zyBqDR8vAdBA/uHlWZyueWpqFNRz1GbPyGkbPGljVnrso5YUH4t5xxLvzweOXeX3ESxez0ELIEOV8xKTZkn2/fOH12vwQlV9vnWNo+6+9OrbTeEP0Ty9P+V+IyD/8PPMzg2/Nae676itUVCb7nMhG/DAA080r2aDHtPgjxDwAhU/Jjs4vLik7MFqbBTUttdCBDfwwAPPJ69u++EXajz/8w/gj9DyMDkS8Jq06f4rc8qa79XYKKhN93kBBg4ES/DAUwvv3VqmVPgD8lcsr32/he3U2iioba8lCJbggQdeubzP2qbt+MlPfvk8/AH5K5ZXs0GdGha7a5laGwW167McwRI88MArddSJSb/3ymv/aQV/QP6K5yWmFf3arz4BCts98PhKQAaCJXjggec9/lO/y3j4A/JXDc/qYOLV3CioXZ9lAkkAgiV44KmF93n7IYeqP/PMG/AH5K8ans3m+bHZ4WLUKP/SVwIQLMEDT628unGjHr72Vl0T/BE6+Yve/YfJDi/PbC94zep03VWj/Mu/HYBgCR54auJ92KTPHPgjZDyu9L/oIkF6THZ4eVanu79a5V9yO6DvCm8wQLAEDzz18Oq0H/Z9jed//iH8ETL5a0QlALx+wgZMdnh5TW27q5rtzG61yv9JxcB5xQFjBIIleOCphPfX91t2gz9CJn+u349wAsA+WMee/Rsw2eHnWZzM36x21z21yp/jtekxz1PfOBLBEjzwFM77uGn/xfBHyOQfxXb7jRQs/c8+WMue/et5vYUx2WHmWR1MNzXLnzva9lyAioHggadg3hdthxzTP/OL9+GPkPC07FGSAPjKFKrxEgA9JlsaXrt2EzSmpJz1apZ/6YqBGQiW4IGnNF7sqPt//NtnMfBHSHg61udcAqDxdY9Ay0sAqmOypeW17DD6z8bkNVfULH/+wsAG5kwEX/DAUxDv3/U6ZSLeh4THOZxLACKFLv1r2AyBSwB0mGw6eDF9F7ZRu/y5I7r3UhFJAIIveODJgfdZG8dWvf4XLyDeB53HXb3nEoAoIflHsNlBVd79Akw2RTyLwzVJ7fIXlwQg+IIHnhx49WKHX/vF7/7WCPE+JDwDLwHQ+lr0x08AokRXCcJkh40Xb8vXm52u79Quf+HbAQi+4IEnF97fP2jXF/E+ZDwuAdAJ+px9UgRvjyDkTynPNND9lmCVQJXVDSh9JQDBFzzw5ML7qFm/JYj3IeUZRK3h4yUAGsiffp7F6Y6D/JlSrYRJEoDgCx548uB9Fj14b7WfPPcu4n1IeXp/yv1GQP7y4VntzATI/wmvbY/5JcWCEHzBA49e3hexI6/86pW3GiPeU8ILVPyYbOl40bZ8rdXBbIb8UTEQPPDkwiNd/t74d7NOiPdoEQxeJXmmNNdLVjtzAfLnVQzstciPOgEI5uCBF07ef+p1zUS8h/zBCxIv3s58ZHa6HkL+T3iPFwaOQfAFDzyKeJ+0SM3/kcdTBfEe8gcviDyz3dUT8i/N8y8JQDAHD7xQ8r5oP+Rojede+hjxHvIHL8i8mg3q1DAmZy+G/MurEzAGwRw88CTk1YsdefOV199vjXgP+YMXIl7Dll+/aByQuxnyf3qL4DKBJADBHDzwQsmrY0x/8Ma/mnZGvIf8wQsxr+VXI35ncbiPQP5lrwQ0tIxBMAcPvDDz3q5ldiI+0yl/0bv/MNny4ZnszJ/MduYy5F9excAxCObggRcm3vsNe0xBfKaSx5X+F10kSI/Jlg8v3sn8F+WCy08CGlpQMRA88ELN+6hF8mqy4h/xmUr5a0QlALx+wgZMtrx4FmdhS8i/LC+612JPA1M6gjl44IWIV6u1c3u1as+/hfhMpfy5fj/CCQD7YB179m/AZMuPVyy8PpB/WV7bnqRscDqCOXjgBZn3efshx5/9xe9qIz5TKf8otttvpGDpf/bBWvbsX8/rLYzJlhPP46lSbs8AFA0qTgIWem8HIJiDB15weHXajbj02z+80xzxmUqelj1KEgBfmUI1XgKgx2TLk9d07twIi5OZDfmX5T3uIoiKgeCBV2n5xw679vs3PopGfKaSp2N9ziUAGl/3CLS8BKA6JlvePNO4LZEWB7MU8i/LI3UCym4RhBzAA0/sUTdu5M0/vVknDvGZSh7ncC4BiBS69K9hMwQuAdBhspXBa9Flhi4uKTcf8i/La993ZXESMBbBHDzw/OTVM468/drbjRMQn6nkcVfvuQQgSkj+EWx2UJV3vwCTrSBe8/adf2kakFME+ZdXMXC5wJUAyAE88Mpc9o9Jv/eXf33ZGfGZWp6BlwBofS364ycAUaKrBGGyZcVrYkz5jXnAmm2Qf/llg8teCYAcwAOvvBK/b37QuhfiM9U8LgHQCfqcfVIEb48g5K9gntmW+4LV6doF+TM+bgdADuCBV/ae/6iH//gkJhnxlHqeQdQaPl4CoIH81cGLtW/4uV9JgIoWED6+EoCKgeCBV0b+MaMfvlvLlIp4Kgue3p9yvxGQv7p4CY6Nz1sdzGbIv/yKgQ3No4uD5AjIATzwyBE76v7fP2jXF/FUYbxAxY/Jlj8v0VZksNgZF+RfTsXAXgtLygZDDuCp+szfOOrum++3+hrxFC2CMdkK43UdvLq61cHkQP4VVQwkuwMyIAfwVFrkZ9QP//fPph0RTyF/TLZCedG2fG2xBJdA/mV57fut9DSyjoMcwFMd74vYETf+/I96FsRTyB+TrYKKgVaH6xvIv7yKgctFFAuCbMBTkvxHXnn1b5/GIJ5C/phslfDq2fpFGpNzJkP+ZXnt+q7wNLKO93E7ALIBTwHybzfs7Cuvv98a8RTyx2SrjFez/hfPGPsvS4b8GT/LBkM24CmgpW/0oAMvvvx6A8RTyB+TrWJebP+l7a2OgruQf9mywY/XBGRANuApilerpYOp8fzPayL+KV/+onf/YbLVy7PY3f+xOlyXIP+nrgR4FwZytwMgG/Dkz/uwab8FUTVqvIL4p3geV/pfdJEgPSZbvbwER8EfrA7mEORf3pqAsaWKBUE24MmOF5f+6L06XUYh/qlG/hpRCQCvn7ABk61uXqK94IVi6RVC/qV5bXst8jQ0Z6BiIHiy5NWNSb9Dqvsh/qlG/ly/H+EEgH2wjj37N2Cywes8tLCad5sg5F+K16734pIkALIBTy68OrHDL772dn0z4p9q5B/FdvuNFCz9zz5Yy57963m9hTHZaud5PFWK5dfFamceQP68ioG9FnlvB6BiIHhy4NWOTtv5y9/+rR7in2p4WvYoSQB8ZQrVeAmAHpMNHn+Yna6aVrvrHOT/VMXA+Al+JgGQF3jh5X3QuN88wwsvvIr4pxqejvU5lwBofN0j0PISgOqYbPDKG/EpeS+ZBqzZBPm7S9UJKLtFEPICT3pePePI229/HDcA8U9VPM7hXAIQKXTpX8NmCFwCoMNkgyfEa9Aq9mfGpOyJkD8qBoJHL++L6GGnf/+XT9oh/qmKx1295xKAKCH5R7DZQVXe/QJMNniieMb+y6zmVPcdFA16fMT0zxa4HQB5gRc+3metUgufe+G3nyJeqY5n4CUAWl+L/vgJQJToKkGYbPBYXnyq+69Wp2sfigbxrwSgYiB40vDqGNMf/Kde53HPP//HnyBeqZLHJQA6QZ+zT4rg7RGE/MELiGeybdFZHUwmigY9SQIal1wJgLzACw/v85hhJ/705hdGxCtV8wyi1vDxEgAN5A9eMHhWp6uu1c5cQNEgxhPTb5X3SgAqBoIXDt5Hzfoteeanv3gf8Ur1PHG793gJAOQPXtB48YM2/sLqcGWjaBBbMdCSiYqB4IWMVyd22LW/f9i+D+IVeH7xAhU/Jhs8X8Nm8/zY4mA6mu3MHdVXDOyzxNOITQIgL/CCyavVyrH5xd/9pSHiFXhoEQwedbwEZ+EbZod7u9qLBkX3WuxHnQDIEDxhXl3jqLvv1e08+tlnf1cD8Qo8yB88anl1W8Y9F9d/ha1YhLdVXTGw70rvwsAG5kzIELyAebXbOLe+/Kf3vkR8AQ/yB082vNbdst40Ja0pUHPRIFInoLHossGQIXi8oj6x6dffrWVNI305EF/Ag/zBkx3vL7a+EVa7K9aa6rqq1roB3rLBPq8EQIbg8e71f5mSxzXxQXwBD/IHT9Y8Y+r6F612Zr5qKwb2W+VpnDCxgiQAMgSPXeEfM/T8mx+07oX4Ah7kD57y6gbYmQbWVOa4GusGeOsElLkdABmCN9pTN2b0w4+a9V/43HOvfIz4Al4w5S969x8mG7xw8DoPLaxmcTD9rM6CW2qrG+BdGFhyJQAyBO/x1r7fv/FRNOILeEHmcaX/RRcJ0mOywQsXLzGt6NdmBzNddRUDbas9TYqTgPrGkZChinm12w8+9WbNtr0rWuSH+AJeJeWvEZUA8PoJGzDZ4IWbZ7bn/cs8IGeLmuoGkDoBpGIgPwmAXNXBqxs38uZ/6nXN1NX46d8RD8ALkfy5fj/CCQD7YB179m/AZIMnBe/zz5s+G9t3iTkuac33aqkbEN17kaexdYw3CYBcVcCLS3/0YTPb8p/95o16iAfghVD+UWy330jB0v/sg7Xs2b+e11sYkw2eJLym0b1ftNjX9zalMpfVUDegXd9lnsYJ/hYLglzlxqvV2uF+9W+fxiAegBdinpY9ShIAX5lCNV4CoMdkg0cDz5S2pUaxNJNMzoJriq8Y2G+lwBZByFXOvFqt7Rtfe6uuCfEAvDDwdKzPuQRA4+segZaXAFTHZINHGy92aOFzFifjsKS6byq6YiBZGNghS2QSALnSzqvdasCO/327cQfEA/DCxOMcziUAkUKX/jVshsAlADpMNng08yyDmZ8VC3NIsSxvK7ZiYD8xvQMgV5p5n7VO2fvX95r0wN8veGHkcVfvuQQgSkj+EWx2UJV3vwCTDZ4seKSioMXJDLWmMteVuHWQJAGPrwSMgVxlxPu0derON2s271uzQZ0a+PsFL8w8Ay8B0Ppa9MdPAKJEVwnCZINHES/GlvOs0bayjzll9RmlbR2MLfd2AGRNG69uu+EPP2nWN//1f3yeiL9f8CTkcQmATtDn7JMieHsEIX/wZM2r3cTyQmy/xSZz0ppdiqoYWLIwcAxkTRmvTmz6Dx827r7wd39+tw3+fsGjgGcQtYaPlwBoIH/wlMQjXQfj7cxHFqd7lWIqBvZb5WmSOMlT35heLKwRkLXEvLrth194r37nsb966Q/18PcLHkU8cbv3eAkA5A+eYnkWO/N6sUBHmZ3MFblvHWzXZ2lJsSDIWhrep20Hbnv747gBz/3yt/+DvzfwZMsLVPyYbPDkyCNNh6xOd2uL3bVezlsH2/Ve7GkcP9Z7JSAwEUL+/vLqxgy7/H6DnjNf/tN7X+LvDTyl8TA54KmKZxno/qPF6R5sdjLn5bh7oH3fZd7bAY/XBGRA1qHgxaU/qtXSWfT3j2P7PPvL//kN/t7Ag/wx2eApiNfgqwXauD5L2hgHrM6NS1l7X067B7xrAhL8TQIgf1+8L6KHnf5vg+6Tf/2Htxvg7w08yB+TDZ4KeC0sg16JtS3rYE4tWGNyFjyURcXA/tmepomTPQ0tYpIAyL8iXp32w76v2aTXrD//vW5sRe148fcGHuSPyQZPBTy20qDFamfyrakFj2jePeCtE5CY5eNKAOT/NK9OzNDzHzbpM+e1t+ubK5I+/j7Ag/wx2eCpmEeqDZodrg4kGTA5mfs0LiD03g7okFXBlQDIn+PVaT/izIdN+s7/33caxttsnh/j7wM8yB+TAx54oniJtiKD2VnY0OJkxltSXSdpWkBIGgiVvR2gbvnXaTf03qctbVvfq/PV6Fder9nK15k+/j7AU7r8Re/+w2SDB17FgxQbatdj2ttx/Vf0NSWtXm9Oyrkn9QJCsiaA3ztAjfKvHe0oPsvvufStD77s99Lv/u8dfJ/BA69U6X/RRYL0mGzwwBPHaxrd+0WLfX3dYmE7i2VcUKZTYbgqBnoXBhYnASZ1VAys3X7wqU9aJGX/u7Zl5O9f/08Mvs/ggVeu/DWiEgBeP2EDJhs88ALjNbXtrmpJc71rcTJdrXb3Qm/NgTAtIPTWCUgYV6pssCLkHzvq/udtB+75oHGv2WR//i9e/uvn+P6BB55P+XP9foQTAPbBOvbs34DJBg+8IPE8nirmgRt+b3G4oq1O93CL07XGmuq+ENKKgQljvVcC5FgxsF7syHtfRA859FGL5NXv1e8y5v/+1STxuV+8+hq+f+CB55f8o9huv5GCpf/ZB2vZs389r7cwJhs88ELAI/3iW3VM/0O7PnMbxNlW9DEmr55lTSnYZnUW3A3GGgLSO6BZxymehpaxVFcM/CJmxLlPW9s3vN+o1wxSZ//3b3wU/fxv/vhLfF/AA69SPC17lCQAvjKFarwEQI/JBg+88PNM47ZExjsKXzWnuT6Jt7uNFifjsDjds6wOZkNxcnDWn9sIsezuACkrBtYzjrj9RbTz+KctkzZ91KTXsvfqJkx854PWqX9+s47x5z//Y018X8ADL+g8HetzLgHQ+LpHoOUlANUx2eCBRyfPZNuis6Zt+LMlzVXbbF/Xzmhb0TsuadXQONuqycbknKXGAbkuc6p7tynV/T2pXfBki+DYoFUMrBc78iYpm/tZ9KC9n7Z2bCCX6j9s0nfufxt8PfGfn3cY+taHsf3//I96ll++8pfa5EoHPl/wwAsbj3M4lwBECl3617AZApcA6DDZ4IGnEJ7HUyVmoPsnCY6NzycMdP/S7NzwW9IMKcFZ+IZpoPstaxrzL6vd/YEljallSl1XJ7bXgrrtesyuHd3zmw/bdZv+XnT3GW/FOtb8PjGt6NekQqIpbUsNcoUCnwd44FHJ467ecwlAlJD8I9jsoCrvfgEmGzzwwAMPPPDkxzPwEgCtr0V//AQgSnSVIEw2eOCBBx544NHG4xIAnaDP2SdF8PYIQv7ggQceeOCBJ1+eQdQaPl4CoIH8wQMPPPDAA0/2PHG793gJAOQPHnjggQceeGrhBSp+TDZ44IEHHnjgKYOHyQEPPPDAAw88yB+TAx544IEHHniQPyYbPPDAAw888CB/TDZ44IEHHnjgQf7ggQceeOCBBx7kDx544IEHHnjg0Sh/0bv/MNnggQceeOCBpwgeV/pfdJEgPSYbPPDAAw888GQvf42oBIDXT9iAyQYPPPDAAw88Wcuf6/cjnACwD9axZ/8GTDZ44IEHHnjgyVb+UWy330jB0v/sg7Xs2b+e11sYkw0eeOCBBx548uJp2aMkAfCVKVTjJQB6TDZ44IEHHnjgyY6nY33OJQAaX/cItLwEoDomGzzwwAMPPPBkx+McziUAkUKX/jVshsAlADpMNnjggQceeODJjsddvecSgCgh+Uew2UFV3v0CTDZ44IEHHnjgyY9n4CUAWl+L/vgJQJToKkGYbPDAAw888MCjjcclADpBn7NPiuDtEYT8wQMPPPDAA0++PIOoNXy8BEAD+YMHHnjggQee7Hnidu/xEgDIHzzwwAMPPPDUwgtU/Jhs8MADDzzwwFMGD5MDHnjggQceeJA/Jgc88MADDzzwIH9MNnjggQceeOBB/phs8MADDzzwwIP8wQMPPPDAAw88yB888MADDzzwwKNR/qJ3/2GywQMPPPDAA08RPK70v+giQXpMNnjggQceeODJXv4aUQkAr5+wAZMNHnjggQceeLKWP9fvRzgBYB+sY8/+DZhs8MADDzzwwJOt/KPYbr+RgqX/2Qdr2bN/Pa+3MCYbPPDAAw888OTF07JHSQLgK1OoxksA9Jhs8MADDzzwwJMdT8f6nEsANL7uEWh5CUB1TDZ44IEHHnjgyY7HOZxLACKFLv1r2AyBSwB0mGzwwAMPPPDAkx2Pu3rPJQBRQvKPYLODqrz7BZhs8MADDzzwwJMfz8BLALS+Fv3xE4Ao0VWCMNnggQceeOCBRxuPSwB0gj5nnxTB2yMI+YMHHnjggQeefHkGUWv4eAmABvIHDzzwwAMPPNnzxO3e4yUAkD944IEHHnjgqYUXqPgx2eCBBx544IGnDB4mBzzwwAMPPPAgf0wOeOCBBx544EH+pX85v0eAIQjlgsEDDzzwwAMPvDDyAvnl/B4B+iCUCwYPPPDAAw888MLIC+SX63j1hasHoVwweOCBBx544IEXRp6/v7wKr0dANV5zgSrggQceeOCBB548eBzTn18exesRoK1kuWDwwAMPPPDAA08aXoTYIkFVeD0CuCOykr8cPPDAAw888MALP08jKgHgPTiSd2iC8MvBAw888MADDzxpeKISgIinjx9VYoAHHnjggQceeFTwqvjKFn7MO6pU8peDBx544IEHHniU8P4ftdpkfJrXwgQAAAAASUVORK5CYII=")

    }

if __name__ == "__main__":
    try:

        app = MiniNAM()

        app.mainloop()

    except KeyboardInterrupt:
        info( "\n\nKeyboard Interrupt. Shutting down and cleaning up...\n\n")
        app.stop()

    except Exception:
        # Print exception
        type_, val_, trace_ = sys.exc_info()
        line = sys.exc_info()[-1].tb_lineno
        errorMsg = ("-" * 80 + "\n" +
                    "Caught exception on line %d." % (line) +
                    " Cleaning up...\n\n" + "%s: %s\n" % (type_.__name__, val_) +
                    "-" * 80 + "\n")
        error(errorMsg)
        # Print stack trace to debug log
        import traceback

        stackTrace = traceback.format_exc()
        debug(stackTrace + "\n")
        app.stop()

