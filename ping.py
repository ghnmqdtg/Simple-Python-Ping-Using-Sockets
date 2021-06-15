import socket
import struct
import time
import sys
import os
import click
from statistics import mean


class Ping():
    
    def __init__(self, target_host, count, timeout, ttl, interval, ipv6, verbose, statistics, sequence=0):
        self.target_host = target_host
        self.count = count
        self.timeout = timeout
        self.ttl = ttl
        self.interval = interval
        self.ipv6 = ipv6
        self.verbose = verbose
        self.sequence = sequence
        self.statistics = statistics

    def ping(self):
        ''' Packet header setting '''
        self.ip_header_len = 60
        self.icmp_header_len = 8
        
        if (self.ipv6):
            self.icmp_echo_request = 128     # ICMP IPv6 ECHO_REQUEST
            self.icmp_echo_reply = 129       # ICMP IPv6 ECHO_REPLY
            self.addr_family = 'AF_INET6'    # IPv6 address family
            sock_af = socket.AF_INET6
            sock_proto = socket.getprotobyname('ipv6-icmp')
        else:
            self.icmp_echo_request = 8       # ICMP IPv4 ECHO_REQUEST
            self.icmp_echo_reply = 0         # ICMP IPv4 ECHO_REPLY
            self.addr_family = 'AF_INET'     # IPv4 address family
            sock_af = socket.AF_INET
            sock_proto = socket.getprotobyname('icmp')
        
        ''' Create the socket object '''
        sock = None
        
        try:
            sock = socket.socket(sock_af, socket.SOCK_RAW, sock_proto)
        except PermissionError:
            print('Fatal: You must be root to send ICMP packets', file=sys.stderr)
            exit(1)
        except:
            print('Fatal: General error in socket()', file=sys.stderr)
            exit(1)
        
        sock.settimeout(self.timeout)
        
        if (self.ipv6):
            # Set IPv6 max hops
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, self.ttl)
        else:
            # IPv4 TTL
            sock.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)

        for seq in range(self.count):
            ''' Prepare for the packet '''
            icmp_code = 0
            icmp_checksum = 0
            # Generate 16 bit ICMP ID
            icmp_id = os.getpid() & 0xffff

            icmp_data = 192 * 'A'
            icmp_data = bytes(icmp_data.encode('utf-8'))

            data_len = len(icmp_data)

            # The time that packet was created
            timestamp_send = time.time()
            # Generate a dummy packet with checksum = 0
            packet = struct.pack(f'BBHHHQ{data_len}s', self.icmp_echo_request, icmp_code,
                                icmp_checksum, icmp_id, self.sequence, int(timestamp_send), icmp_data)
            # Get the checksum
            icmp_checksum = self.checksum(packet)
            # Generate the packet with generated checksum
            packet = struct.pack(f'BBHHHQ{data_len}s', self.icmp_echo_request, icmp_code,
                                icmp_checksum, icmp_id, self.sequence, int(timestamp_send), icmp_data)

            ''' Send the packet '''
            result = self.send_ping(
                sock, packet, data_len, timestamp_send, icmp_id)
            if self.count == 1:
                # Condition ping: Host up or down
                exit(result)
            if (result != 1):
                info_dict['Received'] = info_dict['Received'] + 1
            else:
                info_dict['Lost'] = info_dict['Lost'] + 1

            time.sleep(self.interval)

        sock.close()

        info_dict['Sent'] = self.count
        
        if (self.statistics):
            host = info_dict['Host']
            sent = info_dict['Sent']
            received = info_dict['Received']
            lost = info_dict['Lost']
            percent = (lost / sent) * 100
            min_time = min(info_dict['Time'])
            max_time = max(info_dict['Time'])
            avg_time = round(mean(info_dict['Time']), 2)

            # Print the statistics
            print(f'\nPing statistics for {host}')
            print(f'\tPackets: Sent = {sent}, Received = {received}, Lost = {lost} ({percent}% loss)')
            print('Approximate round trip times in milli-seconds:')
            print(
                f'\tMinimum = {min_time}ms, Maximum = {max_time}ms, Average = {avg_time}ms')

    def send_ping(self, sock, packet, data_len, timestamp_send, icmp_id):
        ''' Get target IP address '''
        # target ip address
        target_addr = None

        # getaddrinfo returns an array of tuples (ainfo) for each address family and socket kind.
        # sockaddr format: IPv4 - (target_host, port), IPv6 - (address, port, flow info, scope id)
        try:
            addr_info = socket.getaddrinfo(self.target_host, 1)[0]
            # addr_info[0].name: address family, AF_INET or AF_INET6
            # addr_info[4]: target ip address
            if addr_info[0].name == self.addr_family:
                target_addr = addr_info[4]
        # It raises an exception if the address is unable to get
        except socket.gaierror:
            print(
                f'Fatal: Unable to get {self.addr_family} address for {self.target_host}', file=sys.stderr)
            exit(1)

        if (self.verbose):
            pkt=struct.unpack('BBHHHQ', packet[:-data_len])
            host = self.target_host
            print(f'Ping: {pkt}, {host}')

        # Send ICMP packet to the target ip address
        try:
            sock.sendto(packet, target_addr)
        except socket.error:
            etype, evalue, etrb = sys.exc_info()
            print(evalue.args[1], file=sys.stderr)
            return 1

        while True:
            # calcsize('Q'): timestamp size
            buffer_size = self.ip_header_len + self.icmp_header_len + struct.calcsize('Q') + data_len

            recv = None
            host = None

            try:
                recv, host = sock.recvfrom(buffer_size)
            except socket.timeout:
                print('Host is down')
                return 1
            except:
                print('Fatal: General error in recvfrom()', file=sys.stderr)
                exit(1)

            timestamp_recv = time.time()

            if (self.ipv6):
                self.ip_header_len = 0
            else:
                # First byte consists of 4 bit IP Version and 4 bit IHL (internet header length)
                version_ihl = struct.unpack('B', recv[:1])[0]
                # Cut the IHL value out
                ihl = ((version_ihl << 4) & 0xff) >> 4
                # Recalculate the IP header length
                self.ip_header_len = 4 * ihl
            
            # The length of received packet
            packet_len = self.ip_header_len + self.icmp_header_len + \
                struct.calcsize('Q') + data_len
            
            # Get packet header info
            packet_header = struct.unpack(
                'BBHHH', recv[self.ip_header_len:self.ip_header_len+self.icmp_header_len])

            if ((packet_header[0] == self.icmp_echo_reply) and (packet_header[3] == icmp_id) and (packet_header[4] == self.sequence)):
                if (self.verbose):
                    pkt = packet_header[:-1]
                    host = host[0]
                    size = packet_len
                    time_spent = (timestamp_recv - timestamp_send) * 1000
                    info_dict['Host'] = host
                    info_dict['Time'].append(round(time_spent, 2))
                    print(f'Pong: {pkt}, {host}, {size}, {time_spent:0.2f}')
                else:
                    if self.count == 1:
                        print('Host is up')
                    else:
                        size = packet_len
                        host = host[0]
                        seq = packet_header[4]
                        time_spent = (timestamp_recv - timestamp_send) * 1000
                        info_dict['Host'] = host
                        info_dict['Time'].append(round(time_spent, 2))
                        print(
                            f'{size} bytes from {host}: seq={seq} ttl={self.ttl} time={time_spent:0.2f} ms')
                
                return 0
            else:
                if timestamp_recv - timestamp_send > self.timeout:
                    print('Host is down')
                    return 1
            
    def checksum(self, source_string):
        sum = 0
        max_count = (int(len(source_string) / 2)) * 2

        for i in range(0, max_count, 2):
            if i + 1 < max_count:
                # Fold 2 neighbour bytes into a number and add it to the sum
                sum = sum + (source_string[i+1] << 8) + source_string[i]
            else:
                # If there is an odd number of bytes, fake the second byte
                sum = sum + source_string[i] + 0

        # # Add carry bit to the sum
        sum = (sum >> 16) + (sum & 0xffff)
        # Invert and truncate to 16 bits
        checksum = ~sum & 0xffff

        return checksum


@click.command()
@click.argument('target_host', required=True)
@click.option('-c', 'count', default=4, help='Number of echo requests to send. Default is 4.')
@click.option('-t', 'timeout', default=2, help='Timeout in milliseconds to wait for each reply.')
@click.option('-m', 'ttl', default=64, help='Time To Live.')
@click.option('-i', 'interval', default=1, help='Interval between two requests in seconds. Default is 1.')
@click.option('-6', 'ipv6', default=False, help='Use IPv6 protocol instead of IPv4.')
@click.option('-v', 'verbose', default=False, help='Verbose the info.')
@click.option('-s', 'statistics', default=True, help='Show the statistics.')
@click.pass_context
def main(ctx, target_host, count, timeout, ttl, interval, ipv6, verbose, statistics, sequence=0):
    ctx.obj = Ping(target_host, count, timeout, ttl, interval,
                   ipv6, verbose, statistics, sequence).ping()

if __name__ == '__main__':
    info_dict = {
        "Host": "",
        "Sent": 0,
        "Received": 0,
        "Lost": 0,
        "Time": []
    }
    main()
