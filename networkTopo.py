#/usr/bin/python
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Host
from mininet.node import OVSKernelSwitch
from mininet.log import setLogLevel, info
from mininet.node import RemoteController
from mininet.term import makeTerm


def myTopo():
    net = Mininet(topo=None, autoSetMacs=True, build=False, ipBase='10.0.1.0/24')

    c1 = net.addController('c1', RemoteController)

    client = net.addHost('client', cls=Host, defaultRoute=None)
    server_1 = net.addHost('server_1', cls=Host, defaultRoute=None)
    server_2 = net.addHost('server_2', cls=Host, defaultRoute=None)

    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, failMode='secure')

    net.addLink(client, s1)
    net.addLink(server_1, s1)
    net.addLink(server_2, s1)

    net.build()

    client.setMAC(intf="client-eth0", mac="00:00:00:00:00:03")
    server_1.setMAC(intf="server_1-eth0", mac="00:00:00:00:00:01")
    server_2.setMAC(intf="server_2-eth0", mac="00:00:00:00:00:02")

    client.setIP(intf="client-eth0", ip='10.0.1.5/24')
    server_1.setIP(intf="server_1-eth0", ip='10.0.1.2/24')
    server_2.setIP(intf="server_2-eth0", ip='10.0.1.3/24')

    net.start()

    net.terms += makeTerm(c1)
    net.terms += makeTerm(s1)
    net.terms += makeTerm(client)
    net.terms += makeTerm(server_1)
    net.terms += makeTerm(server_2)

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    myTopo()
