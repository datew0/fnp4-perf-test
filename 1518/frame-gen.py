from scapy.all import wrpcap, Ether, IP, UDP, TCP, Raw

# UDP 1518
packets = [
    Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=43845, dport=55) / ('5' * 1476),
    Ether() / IP(src="2.2.2.2", dst="1.1.1.1") / UDP(sport=55, dport=43845) / ('5' * 1476),
]
wrpcap('1518/udp.pcap', packets)

# TCP 1518
SYN = TCP(sport=1234, dport=80, flags="S", seq=0, ack=0)
SYNACK = TCP(sport=80, dport=1234, flags="SA", seq=0, ack=1)
ACK = TCP(sport=1234, dport=80, flags="A", seq=1, ack=1)

# Set up the IP and TCP headersand HTTP GET request
get_request = (
    TCP(sport=1234, dport=80, flags="PA", seq=ACK.seq, ack=ACK.ack) /
    Raw(b"GET / HTTP/1.1\r\nHost: 2.2.2.2\r\n\r\n")
)

# Set up the IP and TCP headers for the HTTP response from the server
http_response = (
    TCP(sport=80, dport=1234, flags="PA", seq=ACK.ack, ack=ACK.seq + len(get_request[Raw])) /
    ("HTTP/1.1 200 OK\r\n" + "A" * 1447)
)

response_ack = (
    TCP(sport=1234, dport=80, flags="A", seq=http_response.ack, ack=ACK.seq + len(http_response[Raw]))
)

packets = [
    Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / SYN,
    Ether() / IP(src="2.2.2.2", dst="1.1.1.1") / SYNACK,
    Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / ACK,
    Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / get_request,
    Ether() / IP(src="2.2.2.2", dst="1.1.1.1") / http_response,
    Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / response_ack
]

#Create a PCAP file with the packets
wrpcap("1518/tcp.pcap", packets)