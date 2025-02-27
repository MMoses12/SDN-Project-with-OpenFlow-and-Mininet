#!/usr/bin/python

#You may need to first execute: mn -c

import subprocess
import re
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController, OVSKernelSwitch, UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from mininet.link import Intf
from mininet.util import quietRun

def myNet():

    CONTROLLER_IP='127.0.0.1'

    # Create network
    net = Mininet( controller=RemoteController, link=TCLink, switch=OVSKernelSwitch)

    # Create devices 
    ## Server
    h1 = net.addHost( 'h1', ip='192.168.1.2/24', mac='00:00:00:00:01:02', defaultRoute='via 192.168.1.1' )
    h2 = net.addHost( 'h2', ip='192.168.2.2/24', mac='00:00:00:00:02:02', defaultRoute='via 192.168.2.1' )
    h3 = net.addHost( 'h3', ip='192.168.2.3/24', mac='00:00:00:00:02:03', defaultRoute='via 192.168.2.1' )
    h4 = net.addHost( 'h4', ip='192.168.1.3/24', mac='00:00:00:00:01:03', defaultRoute='via 192.168.1.1' )
    
    ## Switches
    s1a = net.addSwitch( 's1a' , protocols=["OpenFlow10"], dpid='1A' )
    s1b = net.addSwitch( 's1b' , protocols=["OpenFlow10"], dpid='1B' )
    s2 = net.addSwitch( 's2' , protocols=["OpenFlow10"], dpid='2' )
    s3 = net.addSwitch( 's3' , protocols=["OpenFlow10"], dpid='3' )

    #disable ipv6 traffic (Neighbor Discovery packets)
    for h in net.hosts + net.switches:
        h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    # Create links 
    net.addLink(s1a, s1b, port1=1, port2=1)   
    net.addLink(s1a, s2, port1=2, port2=2)   
    net.addLink(s1b, s3, port1=2, port2=2)   
    net.addLink(s2, s3, port1=1, port2=1)   
    net.addLink(h1, s2, port1=1, port2=3)   
    net.addLink(h2, s2, port1=1, port2=4)   
    net.addLink(h3, s3, port1=1, port2=3)   
    net.addLink(h4, s3, port1=1, port2=4)  
    
    # New link between the routers on port 4 (for priority packets).
    net.addLink(s1a, s1b, port1=4, port2=4)

    # Create controllers
    c1 = net.addController( 'c1', ip=CONTROLLER_IP, port=6633)

    net.build()

    # Start controllers and connect switches
    c1.start()
    s1a.start( [c1] )
    s1b.start( [c1] )
    s2.start( [c1] )
    s3.start( [c1] )

    CLI( net )

    net.stop()
    subprocess.call(["mn", "-c"], stdout=None, stderr=None)

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNet()
