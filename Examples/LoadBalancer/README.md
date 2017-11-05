# LoadBalancer

This example uses Ryu SDN controller to implement Server Load Balancing.

This example is a part of [Open-State SDN Project](https://github.com/OpenState-SDN/ryu/wiki/Server-Load-Balancing).

### Installation

* Install OpenFlowState from LoadBalancer directory
  `bash -C install.sh`
  or 
  `bash -c "$(wget -O - http://openstate-sdn.org/install.sh)`

  This will modify your ryu controller so make sure to keep a backup
  of your ryu controller code, if you have any

* Install paping that allows to ping specific ports. The paping binary is
  included in LoadBalancer directory. Just set permissions for it:

  `sudo chmod +x paping`

* Use the MiniNAM file provided in this directory. The `getQueue()` function
  in this file has been modified to add all the packets in same queue, as 
  all the packets in this example belong to same flow. 

### Running

* Launch the server
  `ryu-manager ~/ryu/ryu/app/openstate/forwarding_consistency_1_to_many.py`

* Start MiniNAM and the network:
  `sudo python MiniNAM.py --topo single,4 --mac --switch user --controller remote`

* Start three servers by opening terminals on h2, h3 and h4 and:
  `h2#  python /home/mininam/ryu/ryu/app/openstate/echo_server.py 200`
  `h3#  python /home/mininam/ryu/ryu/app/openstate/echo_server.py 300`
  `h4#  python /home/mininam/ryu/ryu/app/openstate/echo_server.py 400`

* Send pings from client:
  `h1#  ./paping 10.0.0.2 -p 80 -c 20`
