import socket
import struct
from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap

def main():
    pcap = Pcap('capture.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print('Gemio Quispe Jose Miguel\t\nCi: 10906316 LP')
    while True:
        print('________________________________________________________________________')
        raw_data, addr = conn.recvfrom(65535)      
        pcap.write(raw_data)
        eth = Ethernet(raw_data) 
        print('\nEthernet Header')
        print('\tDestination Address:\t{}\n\tSource Address:\t\t{}\n\tProtocol:\t\t{}'.format(eth.dest_mac, eth.src_mac, eth.proto))

        # IPv4
        if eth.proto == 8:
            x = struct.unpack('!BBHHHBBH4s4s' ,eth.data[0:20])
            ipv4 = IPv4(eth.data)
            print('IPv4 Header:')
            print('\tIP Version: \t\t{}\n\tIP Header Length: \t{} DWORDS or {} Bytes\n\tType of service: \t{}'.format(ipv4.version,(ipv4.header_length * 8)//32,ipv4.header_length, str(x[1])))
            print('\tIP Total Length: \t{} bytes\n\tIdentification: \t{}\n\tTTL: \t\t\t{}'.format((x[2]*32//8),str(x[3]), ipv4.ttl))
            print('\tProtocol: \t\t{}\n\tChecksum: \t\t{}\n\tSource IP: \t\t{}\n\tDestination IP: \t{}'.format(ipv4.proto, x[7],ipv4.src, ipv4.target))

            # TCP
            if ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                x = struct.unpack('!HHLLBBHHH',ipv4.data[0:20])
                print('TCP Header')
                print('\tSource Port:\t\t{}\n\tDestination Port: \t{}'.format(tcp.src_port, tcp.dest_port))
                print('\tSequence Number: \t{}\n\tAcknowledge Number: \t{}'.format(tcp.sequence, tcp.acknowledgment))
                print('\tHeader Length:\t\t{} Dwords or {} bytes'.format(x[4] >> 4, ((x[4] >> 4) * 32) // 8) )
                print('\tUrgent Flag: \t\t{}\n\tAcknowledgement flag:\t{} \n\tPush flag: \t\t{}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                print('\tReset flag: \t\t{} \n\tSynchronise flag: \t{} \n\tFinish flag:\t\t{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))
                print('\tWindow: \t\t{}\n\tCheksum: \t\t{}\n\tUrgent Pointer: \t{}'.format(x[6], x[7], x[8]))

             # ICMP
            elif ipv4.proto == 1:
                icmp = ICMP(ipv4.data)
                print('ICMP Header')
                print('\tType:\t\t\t {} \n\tCode:\t\t\t {} \n\tChecksum:\t\t {}'.format(icmp.type, icmp.code, icmp.checksum))
            
            # UDP
            elif ipv4.proto == 17:
                udp = UDP(ipv4.data)
                x = struct.unpack('!HHhH', ipv4.data[0:8])
                print('UDP Header')
                print('\tSource Port: \t\t{} \n\tDestination Port: \t{} \n\tLength: \t\t{} bytes'.format(udp.src_port, udp.dest_port, x[2]))
                print('\tChecksum: \t\t{}'.format(x[3]))
    pcap.close()
main()
