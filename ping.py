import os
import socket
import struct
import select
import time

ICMP_ECHO_REQUEST = 8  # Seems to be the same on Solaris.

ICMP_CODE = socket.getprotobyname('icmp')

ERROR_DESCR = {
    1: ' - Note that ICMP messages can only be '
       'sent from processes running as root.',
    10013: ' - Note that ICMP messages can only be sent by'
           ' users or processes with administrator rights.'
}

class Ping():
    
    def __init__(self, target_host, count=4, timeout=2):
        self.target_host = target_host
        self.count = count
        self.timeout = timeout

    def ping(self):
        target_ip = socket.gethostbyname(self.target_host)
        print(f'Ping {self.target_host} [{target_ip}]')
        for i in range(self.count):
            try:
                ip_header, delay = self.ping_once()
            # Error raised for address-related errors by getaddrinfo() and getnameinfo()
            except socket.gaierror as e:
                print(f'Failed \nsocket error: {e[1]}')
                break

            if (delay == None):
                print(f'Failed \nTimeout within {self.timeout} seconds')
            else:
                ttl = ip_header['ttl']
                delay = round(delay * 1000.0, 4)
                print(f'Reply from {target_ip}: bytes= time={round(delay)}ms TTL={ttl}')

    # Sends one ping to the given target host
    def ping_once(self):
        try:
            current_socket = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
        except socket.error as e:
            # ERROR_DESCR[1] or ERROR_DESCR[10013]: Not superuser, operation not allowed
            if e.errno in ERROR_DESCR:
                # Operation not permitted
                raise socket.error(''.join((e.args[1], ERROR_DESCR[e.errno])))
            raise  # raise the original error
        try:
            host = socket.gethostbyname(self.target_host)
        except socket.gaierror:
            return
        
        # Maximum for an unsigned short int c object counts to 65535 so
        # we have to sure that our packet id is not greater than that.
        packet_id = os.getpid() & 0xffff
        
        self.send_ping(current_socket, packet_id)
        ip_header, delay = self.receive_ping(
            current_socket, packet_id, self.timeout)
        current_socket.close

        return ip_header, delay

    # Send ping to targe host
    def send_ping(self, current_socket, packet_id):
        target_addr = socket.gethostbyname(self.target_host)
        
        tmp_checksum = 0

        # Create header with 0 checksum
        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        header = struct.pack('bbHHh', ICMP_ECHO_REQUEST,
                             0, tmp_checksum, packet_id, 1)
        bytes_in_double = struct.calcsize('d')
        data = (192 - bytes_in_double) * 'Q'
        data = struct.pack('d', time.time()) + bytes(data.encode('utf-8'))

        # Get the checksum on the data and header
        tmp_checksum = self.checksum(header + data)
        header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0,
                             socket.htons(tmp_checksum), packet_id, 1)

        packet = header + data
        while packet:
            sent = current_socket.sendto(packet, (target_addr, 1))
            packet = packet[sent:]
        
        return target_addr

    # Reveive the ping from the socket
    def receive_ping(self, current_socket, packet_id, timeout):
        time_left = timeout
        
        while True:
            start_time = time.time()
            ready = select.select([current_socket], [], [], time_left)
            time_spent = time.time() - start_time

            # Timeout
            if ready[0] == []:
                return
            
            time_received = time.time()
            recv_packet, addr = current_socket.recvfrom(1024)
            
            icmp_header = self.header2dict(
                names=[
                    'type', 'code', 'type',
                    'packet_id', 'seq_number'
                ],
                struct_format='bbHHh',
                data=recv_packet[20:28]
            )

            if icmp_header['packet_id'] == packet_id:
                bytes_in_double = struct.calcsize('d')
                time_sent = struct.unpack('d', recv_packet[28:28+bytes_in_double])[0]
                
                ip_header = self.header2dict(
                    names=[
                        'version', 'type', 'length',
                        'id', 'flags', 'ttl', 'protocol',
                        'checksum', 'src_ip', 'dest_ip'
                    ],
                    struct_format='!BBHHHBBHII',
                    data=recv_packet[:20]
                )
                # Converts an IP address, which is in 32-bit packed format
                # to the popular human readable dotted-quad string format.
                # !: network (= big-endian), I: unsigned int
                # ip = socket.inet_ntoa(struct.pack("!I", ip_header["src_ip"]))
                # print(ip)

                return ip_header, (time_received - time_sent)

            time_left = time_left - time_spent

            if time_left <= 0:
                return

    # Unpack the raw received IP and ICMP header informations to a dict
    def header2dict(self, names, struct_format, data):
        unpacked_data = struct.unpack(struct_format, data)
        return dict(zip(names, unpacked_data))


    def checksum(self, source_string):
        sum = 0
        max_count = (int(len(source_string) / 2)) * 2
        count = 0

        while count < max_count:
            val = source_string[count+1] * 256 + source_string[count]
            sum = sum + val
            # Truncate sum to 32 bits
            sum = sum & 0xffffffff
            count = count + 2
        
        # Handle last byte if applicable (odd-number of bytes)
        # Endianness should be irrelevant in this case
        # Check for odd length
        if max_count < len(source_string):
            sum = sum + ord(source_string[len(source_string)-1])
            sum = sum & 0xffffffff

        # Add high 16 bits to low 16 bits
        sum = (sum >> 16) + (sum & 0xffff)
        # Add carry from above (if any)
        sum = sum + (sum >> 16)
        # Invert and truncate to 16 bits
        answer = ~sum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        return answer


if __name__ == '__main__':
    Ping('127.0.0.1').ping()
    Ping('www.google.com').ping()
