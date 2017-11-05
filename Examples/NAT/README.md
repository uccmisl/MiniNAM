# NAT

This example shows packets flowing through a router that uses NATing for hosts.

### Installation

No installation needed. Just cd to the NAT directory.

Use the MiniNAM.py file provided in this directory as it has been modified to
detect the NAT rule being installed on the router.

### Running

* Start MiniNAM and the network:
  `sudo python MiniNAM.py --config conf.config --custom goodNAT.py --topo mytopo`

  We do not need controller as the router used here is linuxrouter not OpenVSwitch,
  and for switches the default OVSBridge will be used by Mininet.

* Adjust preferences from `Edit->Preferences`. The config file loads default preferences.

* Send ping from h1 (192.168.1.100) to h3 (10.0.0.100) by opening a terminal for h1.

  On the packets, you can see part of IP Address (first and last octect).
  You can notice the change of IP Address once the packet crosses router.
  To see how MiniNAM makes debugging easier, let's try to have a bad rule installed in router.

* Use badNAT.py or change the goodNAT.py as follows:
  `self.cmd( 'sysctl net.ipv4.ip_forward=0' )`

  Now when you create your network, you will see the packets arriving at router but not
  leaving (because ip_forward is not set to 1).

  The visualization in MiniNAM makes it very easy to identify where the problem is in network.

  The logical error in this example is very simple and basic but it shows how MiniNAM can
  simplify debugging when you are building complex protocols.


