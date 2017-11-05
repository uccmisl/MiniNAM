# Routing

Taken from Spanning Tree in Ryu controller, this example creates a network with multiple paths
between hosts. If a path is broken, the controller tries and updates the path, if possible.

### Installation

Place the simple_switch_stp_13.py file in /ryu/ryu/app/ 

### Running

* Start controller:
  `ryu-manager ~/ryu/ryu/app/simple_switch_stp_13.py`

* To see the behavior where routing will not work due to loop, you can run a simple switch
  `ryu-manager ~/ryu/ryu/app/simple_switch_13.py`

* Start MiniNAM:
  `sudo python MiniNAM.py --custom spanning_tree.py --topo mytopo --controller remote`

* Set the switches to OF13 by running following as sudo:
  `ovs-vsctl set Bridge s1 protocols=OpenFlow13`
  `ovs-vsctl set Bridge s2 protocols=OpenFlow13`
  `ovs-vsctl set Bridge s3 protocols=OpenFlow13`

  Wait for controller to configure ports (FORWARD and DISABLE)

* Send ping from h1 (10.0.0.1) to h2 (10.0.0.2). Packets flow through shortest path (s1-s2)

* Set the link (s1-s2) down from Right-Menu of the link and choosing Link Down

* Ping again.
 
  Once the switches are configured, packets can be seen flowing through the other path (s1-s3-s2)

