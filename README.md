# MiniNAM: A Network Animator for Mininet 

A Network Animator for Visualizing Real-Time Packet Flows in Mininet

MiniNAM 1.0.1

### What is MiniNAM?

MiniNAM is a GUI based tool written in Python Tkinter. It provides real-time animation
of any network created by the Mininet emulator. It includes all the components required
to initiate, visualize and modify Mininet network flows in real-time.

MiniNAM allows dynamic modification of preferences and packet filters: a user can view
selective flows with options to color code packets based on the source/destination node
and/or packet type. This establishes MiniNAM as a very powerful tool for debugging network
protocols or teaching, learning and understanding network concepts.

### How to start MiniNAM?

There are three ways to start MiniNAM:

* Start MiniNAM from CLI with a single command. E.g.

  `sudo python MiniNAM.py --topo tree,depth=2,fanout=2 --controller remote`

  To make MiniNAM easier for Mininet users, arguments of MiniNAM have been kept the same 
  as Mininet. This means that all the arguments that can be passed to `mn` utility can be
  passed to MiniNAM too. A list of these arguments can be seen in help:

  `sudo python MiniNAM.py --help`

* Start MiniNAM from CLI and pass custom files. E.g.

  `sudo python MiniNAM.py --custom <custom_file_name> --net net`
  `sudo python MiniNAM.py --custom <custom_file_name> --topo <topo_name>`

  In addition to custom instances that Mininet takes, MiniNAM can also take a network
  instance. The network instance in custom script must be named net (upper or lower case)
 
*  Import MiniNAM in your code and create an instance. The *init* function of MiniNAM takes
   the following arguments:
   `__init__( self, parent=None, cheight=600, cwidth=1000 , net= None, locations={})`

   Threading might be needed for this because MiniNAM will start a Tkinter GUI which should
   run as a main thread. If you have code that you want to run in parallel, use threading. 

### How does MiniNAM work?

When MiniNAM is launched, it starts or loads the Mininet network instance. It then starts
two threads. One to sniff packets on all the network interfaces created by Mininet and the
second for the Tkinter GUI. The GUI displays network nodes and links. If a packet is sniffed
at any interface, it is displayed over the relevant link in GUI after applying user-specific
preferences and filters.

The speed of packet flow can be decreased, if needed, for better visibility. As there can be 
more than one flow in the network at a particular time, MiniNAM tries to identify packets
that belong to the same flow and adds those packets to a separate FIFO queue for each flow.
In this way those packets are displayed one after another, providing a more representable
view. By default, MiniNAM uses packet type, source and destination address to identify flows.
This should work for most legacy protocols such as pings, iperf etc. However if flows in your 
protocol or network do not just rely on IP addresses, you can modify the flow identification
process of MiniNAM by modifying the `getQueue()` function, to suit your needs.

### Features

* Run programs to generate and monitor traffic in real-time using host terminals.

* Set preferences via `Edit->Preferences` to customize the packet flows:

  * Adjust the speed of packet flows.

  * Hide hosts in the topology if there are too many nodes (only at start-up).

  * Color code packets based on the source or destination nodes.

  * Color code packets based on the packet type.

  * Show IP address (first and last octet) on packets.

  * Show a live statistics box with each node on mouse hover.

* Filter out certain packets based on packet type, IP and/or MAC address via `Edit->Filters`.

* Easily save and load preferences and filters using `File` menu.

* Pause the flow display at any time using `Run->Pause`.

* Set a link down and back up again in run-time by right-clicking a link and choosing options.

* Check statistics of every interface in the network via `Run->Show Interfaces Summary`.

### New features in this release

The first release of MiniNAM was just a binary file. This is the first source code release.
Apart from that this is a performance improvement and a bug fix release.

* Issue of creating networks with custom switches when passing a custom file has been fixed. 

* Pop-up menus have been fixed to not disappear on focus out.

* Fixed the issue with typing feedback gone in terminal, if CLI wasn't exited properly.

* The link-delay detection mechanism has been removed. You can modify the source code to
  load link-delay values from your Mininet script if you want.

* Additional options have been added to the preference menu.

* Added option to import MiniNAM in custom code/script and create its instance.

### Installation

MiniNAM is a GUI tool written in Python2.7 with Tkinter and Mininet's Python API. This means
that it requires a DISPLAY environment to run. If you are using Mininet VM via SSH then make
sure to have X forwarding enabled. Also make sure to have Tkinter imaging installed:

`sudo apt-get install python-imaging`

MiniNAM has no additional dependencies and if you have Mininet installed in your machine
then MiniNAM should work fine too. To install Mininet, you can go through a very helpful
[getting started documentation](http://mininet.org/download/) provided by Mininet.

### Documentation

You can find a tutorial to set up and use MiniNAM at:

<http://www.cs.ucc.ie/misl/research/software/mininam/> 

The tutorial also includes three distinct network examples that use MiniNAM to create a
network and display traffic flows. These examples are a good starting point to learn how to
use MiniNAM.

### Support

We kindly ask that should you mention MiniNAM, or use our code, in your publication, that
you would reference the following [paper](http://ieeexplore.ieee.org/document/7899417/):

Ahmed Khalid, Jason J. Quinlan, Cormac J. Sreenan, "MiniNAM: A network animator for
visualizing real-time packet flows in Mininet". In 20th Conference on Innovations in Clouds,
Internet and Networks (ICIN), March 2017 .

You can send any queries, comments or suggestions to:

`a.khalid@cs.ucc.ie or mislgit@cs.ucc.ie`

Whilst we will attempt to provide the best support where possible, we do not guarantee that
any particular support query can, or will be answered to the extent, or within a time frame
that the inquirer is completely satisfied.

Best wishes,

Ahmed Khalid

