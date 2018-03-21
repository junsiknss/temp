from scapy.all import *

def packet(pkt):
    if pkt[TCP].flags == 2:
        print('SYN packet detected port : ' + str(pkt[TCP].sport) + ' from IP Src : ' + pkt[IP].src)
        send(IP(dst=pkt[IP].src, src=pkt[IP].dst)/TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport,ack=pkt[TCP].seq + 1, flags='SA'))


    elif pkt[TCP].flags == 24:
        send(IP(dst=pkt[IP].src, src=pkt[IP].dst)/TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport,ack=(pkt[TCP].seq + pkt[IP].len - 52), seq=pkt[TCP].ack, flags='A'))

        send(IP(dst=pkt[IP].src, src=pkt[IP].dst)/TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport,ack=(pkt[TCP].seq + pkt[IP].len - 52), seq=pkt[TCP].ack, flags='PA')/'HTTP/1.1 200 OK\r\nDate: Wed, 21 Mar 2018 16:28:27 GMT\r\nServer: Apache/2.4.6 (CentOS)\r\nKeep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\nTransfer-Encoding: chunked\r\nContent-Type: text/html; \
charset=UTF-8\r\n\r\n8\r\nattack!\n\r\n')
        

sniff(filter ="tcp", prn=packet, count = 10)
#sniff(iface="eth0", prn=packet, filter="tcp[0xd]&18=2",count=100)

