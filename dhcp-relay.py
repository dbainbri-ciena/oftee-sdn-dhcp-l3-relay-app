#!/usr/bin/env python

import sys
from flask import Flask
from flask_restful import Api, Resource, request
import scapy.all as scapy
import scapy.contrib.openflow3 as of
import netifaces as n
import threading as t
import requests

app = Flask(__name__)
api = Api(app)

# converts a byte list into printable hex string
def hex(d):
    return ''.join('{:02x}'.format(x) for x in d)

# converts a byte list into a big endian number
def num(d):
    v = 0
    for i in d:
        v = v<<8
        v += i
    return v

# used to store the dpid and port associated with a DHCP (BOOTP) transaction ID
xids = {}

# Thread used to sniff for DHCP responses and packet out them back to the
# client
def responder():
    while True:
        ps=scapy.sniff(filter="udp and dst port 68", count=5)
        # Iterate over the packets we recieved looking for BOOTP packets
        for p in ps:
            # Make sure we have a packet we really want to send to the client.
            # Not sure why the sniff filter isn't work, hmm ...
            if scapy.BOOTP in p and p[scapy.UDP].dport == 68:

                # Lookup DPID and port based on transaction ID
                if p[scapy.BOOTP].xid not in xids:
                    print "UNEXPECTED/UNKNOWN XID: %s" % p[scapy.BOOTP].xid
                    sys.stdout.flush()
                    continue

                dpid,port,dst=xids[p[scapy.BOOTP].xid]
                print "XID: %s [RESPONSE]" % p[scapy.BOOTP].xid
                print "    DPID: 0x%s" % hex(dpid)
                print "    PORT: %d" % port
                print "    DST:  %s" % dst
                print "    IP:   %s" % p[scapy.BOOTP].yiaddr
                sys.stdout.flush()

                # Set the DST to the client
                p[scapy.Ether].dst = dst

                # Create an OF packet out and send it back through OFTEE
                po = of.OFPTPacketOut(data=p)
                po.in_port = 0xffffffff # ANY PORT
                po.actions = [of.OFPATOutput(port=port, pad=[0,0,0,0])]
                po.len = len(bytes(po))
                po.actions_len = 16
                res = requests.post(url='http://oftee:8000/oftee/0x%s' % hex(dpid),
                    data=bytes(po),
                    headers={'Content-Type': 'application/octet-stream'})

@app.route('/packet', methods=['POST'])
def packet_in():
    data = bytearray(request.data)
    dpid = data[0:8]
    port = data[8:12]
    pi = of.OFPTPacketIn(data[12:])
    packet = pi.data

    # store the transaction information for later
    print "XID: %s [PROXIED]" % packet[scapy.BOOTP].xid
    print "    DPID: 0x%s" % hex(data[0:8])
    print "    PORT: %d" % num(data[8:12])
    print "    DST:  %s" % packet[scapy.Ether].src
    sys.stdout.flush()
    xids[packet[scapy.BOOTP].xid] = (
            data[0:8],
            num(data[8:12]),
            packet[scapy.Ether].src)

    # ARP the DHCP server to get IP and MAC
    dhcpd=scapy.sr(scapy.ARP(op=scapy.ARP.who_has, pdst='dhcpd'))

    # muck with the packet to L3 proxy it to the real server
    packet[scapy.IP].src=str(n.ifaddresses("eth2")[n.AF_INET][0]['addr'])
    packet[scapy.Ether].src=n.ifaddresses("eth2")[n.AF_LINK][0]['addr']
    packet[scapy.IP].dst=dhcpd[0][scapy.ARP].res[0][1].psrc
    packet[scapy.Ether].dst=dhcpd[0][scapy.ARP].res[0][1].hwsrc

    # reset the packet checksums
    del packet[scapy.IP].chksum
    del packet[scapy.UDP].chksum
    packet = packet.__class__(str(packet))
    out = packet[scapy.IP]
    del out[scapy.IP].chksum
    del out[scapy.UDP].chksum
    out = out.__class__(str(out))

    # send the packet to the proxy, bye-bye
    r = scapy.send(out[scapy.IP])
    return "", 201

# Start the capture thread
capture = t.Thread(target=responder)
capture.daemon = True
capture.start()

# Start the proxy app, listening for packet in requests from OFTEE
app.run(host='0.0.0.0', debug=True)
