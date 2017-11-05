#!/usr/bin/env bash

# OpenState install script for Mininet 2.2.1 on Ubuntu 14.04
# (https://github.com/mininet/mininet/wiki/Mininet-VM-Images)
# This script is based on "Mininet install script" by Brandon Heller
# (brandonh@stanford.edu)
#
# Authors: Davide Sanvito, Luca Pollini, Carmelo Cascone

# Exit immediately if a command exits with a non-zero status.
set -e

# Exit immediately if a command tries to use an unset variable
set -o nounset

function of13 {
    echo "Installing OpenState switch implementation based on ofsoftswitch13..."
    
    cd ~/

    if [ -d "ofsoftswitch13" ]; then
        read -p "A directory named ofsoftswitch13 already exists, by proceeding \
it will be deleted. Are you sure? (y/n) " -n 1 -r
        echo    # (optional) move to a new line
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo rm -rf ~/ofsoftswitch13
        else
            echo "User abort!"
            return -1
        fi
    fi
    git clone https://github.com/OpenState-SDN/ofsoftswitch13.git

    # Resume the install:
    cd ~/ofsoftswitch13
    ./boot.sh
    ./configure
    make
    sudo make install
    cd ~/
    
    sudo chown -R mininam ~/ofsoftswitch13
}

# Install RYU
function ryu {
    echo "Installing RYU controller with OpenState support..."
    
    # install Ryu dependencies"
    sudo apt-get -y install autoconf automake g++ libtool python make libxml2 \
        libxslt-dev python-pip python-dev
    sudo pip install gevent

    # install libraries for SPIDER
    sudo apt-get -y install python-matplotlib
    sudo pip install pbr pulp networkx fnss

    # fetch RYU
    cd ~/
    if [ -d "ryu" ]; then
        read -p "A directory named ryu already exists, by proceeding it will be \
deleted. Are you sure? (y/n) " -n 1 -r
        echo    # (optional) move to a new line
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo rm -rf ~/ryu
        else
            echo "User abort!"
            return -1
        fi
    fi
    git clone https://github.com/OpenState-SDN/ryu.git ryu
    cd ryu
    
    # install ryu
    sudo pip install -r tools/pip-requires
    sudo pip install -I six==1.9.0
    sudo python ./setup.py install

    sudo chown -R mininam ~/ryu
}

sudo apt-get update
~/mininet/util/install.sh -nt
ryu
of13

echo "All set! To start using OpenState please refer to \
http://openstate-sdn.org for some example applications."
