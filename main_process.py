from __future__ import absolute_import
from __future__ import print_function
import socket
import struct
import sys
import dpkt
import os
import csv
import numpy as np
from binascii import hexlify
from asn1crypto import x509
from TLSStream import TLSStream
from constants import PRETTY_NAMES


stream_buffer = {}  # buffer存储的是某条单向流中TLS块的部分数据，用于组合成完整的TLS块
tcp_stream_dict = dict()  # tcp流字典，存储tcp流信息
encrypted_streams = []  # 当一条TLS流握手完成，建立了完整的连接时，存储此connection信息
flow_directions = {}  # 标识每一个connection单向流的方向，（1）client->server （2）server->client
flow_direction = None  # 临时变量，用于标记当前流方向，仅用于parse_extension
ssl_servers_certs = {}  # 在TLS1.2之前的版本，证书不加密，可以直接提取。此字典存储证书信息（TLS1.2下）
TLSStream_dict = dict()  # TLS流字典，存储TLS流信息
ADUs_dict = dict()  # 记录当前pcap包中每条TLS流中的突发（代表client和server交互的一组数据，以server发送数据后紧接着client发送数据作为分界线，输出至每个pcap包生成的csv文件中）
ADU_nums = 0  # 记录每个pcap包中所有突发数据的个数
#  ################### extract the list of all server_name
application_list_by_server_name = dict()  # 用于生成'按域名划分'目录下的csv文件
#  ################### this global var should not in clean_all_param()


class Extension(object):
    """
    Encapsulates TLS extensions.
    """
    def __init__(self, ip, payload):
        self._type_id, payload = unpacker('H', payload)
        self._type_name = pretty_name('extension_type', self._type_id)
        self._length, payload = unpacker('H', payload)
        # Data contains an array with the 'raw' contents
        self._data = None
        # pretty_data contains an array with the 'beautified' contents
        self._pretty_data = None
        if self._length > 0:
            self._data, self._pretty_data = parse_extension(ip, payload[:self._length],
                                                            self._type_name)

    def __str__(self):
        # Prints out data array in textual format
        return '{0}: {1}'.format(self._type_name, self._pretty_data)

    def __length__(self):
        return self._length


class TcpStream(object):
    """
        Save the Seq and Ack numbers of one direction Tcp-stream.
    """

    def __init__(self, src, dst, src_port, dst_port, seq, ack, ts):
        self.src = src
        self.dst = dst
        self.sport = src_port
        self.dport = dst_port
        self.start_time = ts
        self.end_time = ts
        self.final_packet_bytes = 0
        self.seq = seq
        self.ack = ack
        self.Fin = False
        # self.final_seq = None
        # self.final_ack = None
        # self.valid = True

    def __Fin__(self):
        return self.Fin

    def duration(self):
        return self.end_time - self.start_time


def analyze_packet(ts, pkt_num, packet):
    """
    Main analysis loop for pcap.
    Input:
    'ts': Time stamp of current message.
    'pkt_num': Serial number of current message.
    'packet': Current full frame.
    """
    eth = dpkt.ethernet.Ethernet(packet)
    try:
        if isinstance(eth.data, dpkt.ip.IP):
            parse_ip_packet(ts, pkt_num, eth.data)
    except dpkt.dpkt.NeedData:
        return


def parse_ip_packet(ts, pkt_num, ip):
    """
    Parses IP packet.
    Input:
    'ts': Time stamp of current message.
    'pkt_num': Serial number of current message.
    'ip': Current full IP protocol package.
    """
    sys.stdout.flush()
    # if isinstance(ip.data, dpkt.tcp.TCP) and len(ip.data.data):
    try:
        if isinstance(ip.data, dpkt.tcp.TCP):
            parse_tcp_packet(ts, pkt_num, ip)
    except dpkt.dpkt.NeedData:
        return


def get_dict_key(ip):
    """
    Get dict keys from ip-packet.
    Always return the min-ip,min-ip-port,max-ip,max-ip-port.
    The purpose is to provide a unique key value for each flow in the dictionary.

    Input:
    'ip': Current full IP protocol package.
    """
    if ip.src >= ip.dst:
        ip_src = socket.inet_ntoa(ip.dst)
        ip_sport = ip.data.dport
        ip_dst = socket.inet_ntoa(ip.src)
        ip_dport = ip.data.sport
    else:
        ip_src = socket.inet_ntoa(ip.src)
        ip_sport = ip.data.sport
        ip_dst = socket.inet_ntoa(ip.dst)
        ip_dport = ip.data.dport
    return ip_src, ip_sport, ip_dst, ip_dport


def judge_tcp_packet_correct(ts, pkt_num, ip):
    """
        Judge the retransmission or out-of-order tcp packet of tcp stream.
        Input:
        'ts': Time stamp of current message.
        'pkt_num': Serial number of current message.
        'ip': Current full IP protocol package.
        Returns:
            'Correct':This pkt is correct,its seq and ack is Perfect fit with last pkt.

            'False':This pkt is wrong, so the tcp stream of this pkt is wrong too.

            'Retransmission':This is a retransmission pkt.

            'out-of-order-data':This pkt was out of order, and its length > 0.

            'out-of-order-0-bytes':This pkt was out of order, and its length = 0.

            'Not all Ack':This pkt is also correct, but its seq and ack was not new, maybe the new ack pkt has
                            sent but not received.
    """
    global tcp_stream_dict
    connection = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip.src),
                                          ip.data.sport,
                                          socket.inet_ntoa(ip.dst),
                                          ip.data.dport)
    connection_reverse = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip.dst),
                                                  ip.data.dport,
                                                  socket.inet_ntoa(ip.src),
                                                  ip.data.sport)
    if connection not in tcp_stream_dict.keys():
        if bool(ip.data.flags & dpkt.tcp.TH_SYN) and not bool(ip.data.flags & dpkt.tcp.TH_ACK):
            # TCP packet of SYN.(First Handshake)
            tcp_current_stream = TcpStream(socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst),
                                           ip.data.sport, ip.data.dport, ip.data.seq, ip.data.ack, ts)
            tcp_stream_dict[connection] = tcp_current_stream

            tcp_current_stream.seq = ip.data.seq
            tcp_current_stream.ack = ip.data.ack
            tcp_stream_dict[connection] = tcp_current_stream
            return 'Correct'
        elif bool(ip.data.flags & dpkt.tcp.TH_SYN) and bool(ip.data.flags & dpkt.tcp.TH_ACK):
            # TCP packet of SYN & ACK.(Second Handshake)
            tcp_current_stream = TcpStream(socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst),
                                           ip.data.sport, ip.data.dport, ip.data.seq, ip.data.ack, ts)
            tcp_stream_dict[connection] = tcp_current_stream

            if connection_reverse in tcp_stream_dict.keys():
                tcp_reverse_stream = tcp_stream_dict[connection_reverse]
                if ip.data.ack == tcp_reverse_stream.seq + 1:
                    tcp_current_stream.seq = ip.data.seq
                    tcp_current_stream.ack = ip.data.ack
                    tcp_stream_dict[connection] = tcp_current_stream
                    return 'Correct'
                else:
                    return 'False'
            else:
                print('The connection {0} is not a correct stream'.format(connection))
                return 'False'
        else:
            print('The connection {0} is not a correct stream'.format(connection))
            return 'False'
    elif connection in tcp_stream_dict.keys():
        tcp_current_stream = tcp_stream_dict[connection]
        tcp_current_stream.end_time = ts
        if tcp_current_stream.Fin:
            return 'Correct'
        if bool(ip.data.flags & dpkt.tcp.TH_ACK):
            if tcp_current_stream.ack == 0:  # TCP packet of ACK.(Third Handshake)
                tcp_current_stream.seq = ip.data.seq
                tcp_current_stream.ack = ip.data.ack
                tcp_stream_dict[connection] = tcp_current_stream
                return 'Correct'
        if connection_reverse not in tcp_stream_dict.keys():
            return 'False'
        tcp_reverse_stream = tcp_stream_dict[connection_reverse]
        if tcp_reverse_stream.Fin:
            return 'Correct'
        if bool(ip.data.flags & dpkt.tcp.TH_FIN):
            tcp_current_stream.seq = ip.data.seq
            tcp_current_stream.ack = ip.data.ack
            tcp_current_stream.final_packet_bytes = len(ip.data.data)
            tcp_current_stream.Fin = True
            tcp_reverse_stream.Fin = True
            tcp_stream_dict[connection] = tcp_current_stream
            tcp_stream_dict[connection_reverse] = tcp_reverse_stream
            return 'Correct'
        if ip.data.seq == tcp_current_stream.seq and ip.data.ack == tcp_current_stream.ack \
                and len(ip.data.data) == tcp_current_stream.final_packet_bytes:
            if not bool(ip.data.flags & dpkt.tcp.TH_FIN) and not bool(ip.data.flags & dpkt.tcp.TH_RST):
                # retransmission packet
                print('Find a retransmission packet of connection {0},timestamp is {1},packet number is {2}'
                      .format(connection, ts, pkt_num))
                return 'Retransmission'
            else:
                return 'Correct'
        if ip.data.seq == tcp_reverse_stream.ack and (ip.data.ack == tcp_reverse_stream.seq +
                                                      tcp_reverse_stream.final_packet_bytes):
            tcp_current_stream.seq = ip.data.seq
            tcp_current_stream.ack = ip.data.ack
            tcp_current_stream.final_packet_bytes = len(ip.data.data)
            tcp_stream_dict[connection] = tcp_current_stream
            return 'Correct'
        elif ip.data.seq == tcp_reverse_stream.ack and (ip.data.ack < tcp_reverse_stream.seq +
                                                        tcp_reverse_stream.final_packet_bytes):
            tcp_current_stream.seq = ip.data.seq
            tcp_current_stream.ack = ip.data.ack
            tcp_current_stream.final_packet_bytes = len(ip.data.data)
            tcp_stream_dict[connection] = tcp_current_stream
            return 'Not all Ack'
        elif ip.data.ack >= tcp_current_stream.ack and (ip.data.seq == tcp_current_stream.seq +
                                                        tcp_current_stream.final_packet_bytes):
            tcp_current_stream.seq = ip.data.seq
            tcp_current_stream.ack = ip.data.ack
            tcp_current_stream.final_packet_bytes = len(ip.data.data)
            tcp_stream_dict[connection] = tcp_current_stream
            return 'Correct'
        elif len(ip.data.data) == 0:  # out-of-order packet,but length is 0
            if bool(ip.data.flags & dpkt.tcp.TH_FIN):
                tcp_current_stream.Fin = True
                tcp_reverse_stream.Fin = True
                tcp_stream_dict[connection] = tcp_current_stream
                tcp_stream_dict[connection_reverse] = tcp_reverse_stream
                return 'Correct'
            elif tcp_current_stream.Fin or tcp_reverse_stream.Fin:
                return 'Correct'
            else:
                tcp_current_stream.seq = ip.data.seq
                tcp_current_stream.ack = ip.data.ack
                tcp_current_stream.final_packet_bytes = len(ip.data.data)
                tcp_stream_dict[connection] = tcp_current_stream
                print('Find a out-of-order-0-bytes packet of connection {0},timestamp is {1},packet number is '
                      '{2}'.format(connection, ts, pkt_num))
                return 'out-of-order-0-bytes'
        elif len(ip.data.data) > 0:
            tcp_current_stream.seq = ip.data.seq
            tcp_current_stream.ack = ip.data.ack
            tcp_current_stream.final_packet_bytes = len(ip.data.data)
            tcp_stream_dict[connection] = tcp_current_stream
            print(
                'Find a out-of-order-data packet of connection {0},timestamp is {1},packet number is {2}'.format(
                    connection, ts, pkt_num))
            return 'out-of-order-data'  # maybe include out-of-order packet,but packet is not 0 bytes.
    else:
        print('The connection {0} is not a correct stream'.format(connection))
        return 'False'


def parse_tcp_packet(ts, pkt_num, ip):
    """
    Parses TCP packet.
    Input:
    'ts': Time stamp of current message.
    'pkt_num': Serial number of current message.
    'ip': Current full IP protocol package.
    """
    """ refer: The Transport Layer Security (TLS) Protocol URL:https://tools.ietf.org/html/rfc5246

        enum {

              change_cipher_spec(20), alert(21), handshake(22),

              application_data(23), (255)

          } ContentType;

        """
    global stream_buffer
    global encrypted_streams
    global flow_directions
    global TLSStream_dict
    error = False
    out_of_order = False
    connection = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip.src),
                                          ip.data.sport,
                                          socket.inet_ntoa(ip.dst),
                                          ip.data.dport)
    judgement_result = judge_tcp_packet_correct(ts, pkt_num, ip)
    if judgement_result == 'Retransmission':
        return
    elif judgement_result == 'False':
        error = True
    elif judgement_result == 'Correct' or judgement_result == 'Not all Ack':
        error = False
    elif judgement_result == 'out-of-order-data':
        error = False
        out_of_order = True
    elif judgement_result == 'out-of-order-0-bytes':
        error = False  # Strictly without disorder
    ip_src, ip_sport, ip_dst, ip_dport = get_dict_key(ip)
    if ip.data.sport == 443 or ip.data.dport == 443:
        # If not find this flow in the stream dict,then establish a new flow and deposit in dict.
        if (ip_src, ip_sport, ip_dst, ip_dport) not in TLSStream_dict.keys():
            tls_stream = TLSStream(socket.inet_ntoa(ip.src), ip.data.sport, socket.inet_ntoa(ip.dst),
                                   ip.data.dport, ts, pkt_num)
            tls_stream.total_tcp_flow_bytes += len(ip.data.data)
            if error:
                tls_stream.valid = False
            TLSStream_dict[(ip_src, ip_sport, ip_dst, ip_dport)] = tls_stream
        # If this flow existences, then update it!
        else:
            tls_stream = TLSStream_dict[
                (ip_src, ip_sport, ip_dst, ip_dport)]
            tls_stream.total_tcp_flow_bytes += len(ip.data.data)
            tls_stream.end_time = ts
            fin = bool(ip.data.flags & dpkt.tcp.TH_FIN)  # 取出当前pkt的FIN标志位
            if fin:
                tls_stream.fin_time = ts
            if error:
                tls_stream.valid = False
            if out_of_order:  # 若乱序报文占比超过一定限度则丢弃，由于统计方法问题，实际丢包的数目和占比应该为此处统计值的一半
                tls_stream.stream_error_nums = tls_stream.stream_error_nums + 1
                length = len(tls_stream.TLS_application_data_sequences)
                if length < 10:
                    length = 10
                if (tls_stream.stream_error_nums/length > 0.3) or tls_stream.stream_error_nums > 6:
                    tls_stream.valid = False
            TLSStream_dict[(ip_src, ip_sport, ip_dst, ip_dport)] = tls_stream
    # If the length of tcp-data is 0, do not need to parse it.
    if not len(ip.data.data):
        return
    if connection in encrypted_streams:
        print('Encrypted data between {0}, adds {1} bytes(seq {2}) of Encrypted Data'
              .format(connection, len(ip.data.data), ip.data.seq))
        # Record TCP-data message sequence information.
        if (ip_src, ip_sport, ip_dst, ip_dport) in TLSStream_dict.keys():
            tls_stream = TLSStream_dict[(ip_src, ip_sport, ip_dst, ip_dport)]
            tcp_packet_sequence = '({0},{1}):{2}'.format(pkt_num, ts, len(ip.data.data))
            if connection in flow_directions:
                # The direction of flow is from client-->server.
                if flow_directions[connection] == 'client2server':
                    tls_stream.TLSFlows_client_to_server.append(tcp_packet_sequence)
                    # tls_stream.Flows_client_to_server.append('[{0}, {1}],'.format(ts, len(ip.data.data) - 5))
                # The direction of flow is from server-->client.
                elif flow_directions[connection] == 'server2client':
                    tls_stream.TLSFlows_server_to_client.append(tcp_packet_sequence)
                tls_stream.TLSFlows_both_c2s_and_s2c.append(tcp_packet_sequence)
                TLSStream_dict[(ip_src, ip_sport, ip_dst, ip_dport)] = tls_stream
            else:
                print('This connection({0}) has error!'.format(connection))
    # If TLS type is change_cipher_spec(20)、alert(21) or handshake(22), further decompress it.
    if (ip.data.data[0]) in {20, 21, 22}:
        stream = ip.data.data
    else:
        # Maybe the TLS-data of the current connection is incomplete, the data is segmented into pieces,
        # Collect it until the condition is met and then parse it.
        if connection in stream_buffer:
            print('Added sequence number {0:12d} to buffer'.format(ip.data.seq))
            stream = stream_buffer[connection] + ip.data.data
            del stream_buffer[connection]
            if len(stream) > 10000:
                print('Flushed buffer ({0} bytes)'.format(len(stream)))
        else:
            # Find the application data(23) type, and it in the normal encrypted flow.
            if ip.data.data[0] == 23 and connection in encrypted_streams:
                stream = ip.data.data
            else:
                return
    parse_tls_records(ts, pkt_num, ip, stream)


def add_to_buffer(ip, partial_stream):
    """
    Adds partial_stream of ip to global stream buffer.
    When finding the length-flag of the first tls-record is not equal with its true length,this function will be used.
    Input:
    'ip': Current full IP protocol package.
    'partial_stream': Incomplete TLS data.
    """
    global stream_buffer
    global TLSStream_dict
    connection = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip.src),
                                          ip.data.sport,
                                          socket.inet_ntoa(ip.dst),
                                          ip.data.dport)
    stream_buffer[connection] = partial_stream
    # Finding and retrieving stream Dictionaries, begin
    ip_src, ip_sport, ip_dst, ip_dport = get_dict_key(ip)
    if (ip.data.sport == 443 or ip.data.dport == 443) and (
            ip_src, ip_sport, ip_dst, ip_dport) in TLSStream_dict.keys():
        tls_stream = TLSStream_dict[(ip_src, ip_sport, ip_dst, ip_dport)]
    # Finding and retrieving stream Dictionaries, end
        tls_stream.stream_buffer += len(partial_stream)
        TLSStream_dict[(ip_src, ip_sport, ip_dst, ip_dport)] = tls_stream
    print('Added {0} bytes (seq {1}) to streambuffer for {2}'.format(len(partial_stream), ip.data.seq, connection))


def parse_tls_records(ts, pkt_num, ip, stream):
    """
    Parses TLS Records.
    Input:
    'ts': Time stamp of current message.
    'pkt_num': Serial number of current message.
    'ip': Current full IP protocol package.
    'stream': TCP data field —— TLS protocol content.
    """
    try:
        records, bytes_used = dpkt.ssl.tls_multi_factory(stream)
    except dpkt.ssl.SSL3Exception as exception:
        print('exception while parsing TLS records: {0}'.format(exception))
        return
    connection = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip.src),
                                          ip.data.sport,
                                          socket.inet_ntoa(ip.dst),
                                          ip.data.dport)
    global encrypted_streams
    global flow_directions
    global ADU_nums
    global ADUs_dict
    global TLSStream_dict
    if bytes_used != len(stream):
        # finding the length-flag of tls-record is not equal with its true length
        add_to_buffer(ip, stream[bytes_used:])
    if len(records) > 1:
        # This tcp packet has more than one record.
        print("TLS stream has many({}) records!".format(len(records)))
    record_num = 0
    # parse each record one by one.
    for record in records:
        print("The content of record[{}]:".format(record_num))
        record_type = pretty_name('tls_record', record.type)
        print('captured TLS record type {0}'.format(record_type))
        if record_type == 'handshake':
            parse_tls_handshake(ip, record.data, ts)
            print(record.data)
        if record_type == 'alert':
            parse_alert_message(connection, record.data)
        if record_type == 'change_cipher':
            ip_src, ip_sport, ip_dst, ip_dport = get_dict_key(ip)
            # Finding and retrieving stream Dictionaries, begin
            if (ip.data.sport == 443 or ip.data.dport == 443) and (
                    ip_src, ip_sport, ip_dst, ip_dport) in TLSStream_dict.keys():
                tls_stream = TLSStream_dict[(ip_src, ip_sport, ip_dst, ip_dport)]
                # Finding and retrieving stream Dictionaries, end
                if tls_stream.client_ip == ip.src and tls_stream.client_port == ip.data.sport:
                    # client change cipher spec
                    if not tls_stream.client_ciper_change_spec_flag:
                        tls_stream.client_ciper_change_spec_flag = True
                elif tls_stream.server_ip == ip.src and tls_stream.server_port == ip.data.sport:
                    # server change cipher spec
                    if not tls_stream.server_ciper_change_spec_flag:
                        tls_stream.server_ciper_change_spec_flag = True
                TLSStream_dict[
                    (ip_src, ip_sport, ip_dst, ip_dport)] = tls_stream
            print('[+] Change cipher - encrypted messages from now on for {0}'.
                  format(connection))
            encrypted_streams.append(connection)
        # When record type is application_data.
        if record_type == 'application_data' and connection in encrypted_streams:
            # Each connection has a direction mark inside flow_directions.
            # Information from client or server Hello message.
            if connection in flow_directions:
                ip_src, ip_sport, ip_dst, ip_dport = get_dict_key(ip)
                # Finding and retrieving stream Dictionaries, begin
                if (ip.data.sport == 443 or ip.data.dport == 443) and (
                        ip_src, ip_sport, ip_dst, ip_dport) in TLSStream_dict.keys():
                    tls_stream = TLSStream_dict[
                        (ip_src, ip_sport, ip_dst, ip_dport)]
                    tls_stream.total_tls_flow_bytes += len(record.data)
                # Finding and retrieving stream Dictionaries, end
                if flow_directions[connection] == 'server2client':
                    # Finding and retrieving stream Dictionaries, begin
                    if (ip.data.sport == 443 or ip.data.dport == 443) and \
                            (ip_src, ip_sport, ip_dst, ip_dport) in TLSStream_dict.keys():
                        tls_stream = TLSStream_dict[(ip_src, ip_sport, ip_dst, ip_dport)]
                    # Finding and retrieving stream Dictionaries, end
                        if tls_stream.certs_len_calculate_flag:  # 在捕获到TLS版本为1.3时，此标志才为真，将第一个application data记为证书长度
                            # TLS version is 1.3
                            # So the first application_data of server is the part Server_Hello message and cert.
                            tls_stream.certs_len_calculate_flag = False
                            tls_stream.certs_len_calculate = len(record.data)
                            tls_stream.TLS_application_data_sequences.append(np.array([-len(record.data), ts]))
                            TLSStream_dict[(ip_src, ip_sport, ip_dst, ip_dport)] = tls_stream
                            print('*TLS1.3*  maybe found certificate * The first application data between {0}, '
                                  'this application data length is {1}'.format(connection, len(record.data)))
                        else:
                            # push the application data in its stream_dict().
                            application_sequence = '[{0},{1}]:{2}'.format(pkt_num, ts, len(record.data))
                            tls_stream.server_applications.append(application_sequence)
                            tls_stream.TLS_application_data_sequences.append(np.array([-len(record.data), ts]))
                            application_sequence_to_divide_by_server_name = [pkt_num, ts, len(record.data)]
                            tls_stream.server_application_sequence_to_divide_by_server_name.append(
                                application_sequence_to_divide_by_server_name)
                            # Put server_application_data message in the server_application_list,
                            # The purpose is to differentiate between ADUs
                            # application_sequence_for_list = '{0}      [{1}]'.format(len(record.data), pkt_num)
                            application_sequence_for_list = ['{0}'.format(ts), '{0}'.format(len(record.data))]
                            # Show the flow information intuitively in csv.
                            if tls_stream.last_application_direction is None:
                                """
                                    After the stream is established,the server sends an application_data before the 
                                client sends a request.
                                    *The first application_data of server in TLS1.3 is not calculated here and has been
                                excluded.
                                """
                                tls_stream.last_application_direction = 'server'
                                tls_stream.server_application_list.append(application_sequence_for_list)
                                tls_stream.temp_var_of_server_application_num += 1
                                # arrange_ADUs_in_order
                                tls_stream.current_ADU_pkt_num = pkt_num
                                l_client = [tls_stream.server_name, tls_stream.client_port, pkt_num, ts, ts, 'client:']
                                l_server = ['', '', '', '', '', 'server:', len(record.data)]
                                ADUs_dict[tls_stream.current_ADU_pkt_num] = [l_client, l_server]
                                ADU_nums += 1
                            elif tls_stream.last_application_direction == 'server':
                                tls_stream.server_application_list.append(application_sequence_for_list)
                                tls_stream.temp_var_of_server_application_num += 1
                                # arrange_ADUs_in_order
                                l_client, l_server = ADUs_dict[tls_stream.current_ADU_pkt_num]
                                l_client[4] = ts  # update the ADU_end_time
                                l_server.append(len(record.data))
                                ADUs_dict[tls_stream.current_ADU_pkt_num] = [l_client, l_server]
                            elif tls_stream.last_application_direction == 'client':
                                tls_stream.server_application_list.append(application_sequence_for_list)
                                tls_stream.temp_var_of_server_application_num += 1
                                # arrange_ADUs_in_order
                                l_client, l_server = ADUs_dict[tls_stream.current_ADU_pkt_num]
                                l_client[4] = ts  # update the ADU_end_time
                                l_server.append(len(record.data))
                                ADUs_dict[tls_stream.current_ADU_pkt_num] = [l_client, l_server]
                            tls_stream.last_application_direction = 'server'

                elif flow_directions[connection] == 'client2server':
                    # Finding and retrieving stream Dictionaries, begin
                    if (ip.data.sport == 443 or ip.data.dport == 443) and (
                            ip_src, ip_sport, ip_dst, ip_dport) in TLSStream_dict.keys():
                        tls_stream = TLSStream_dict[
                            (ip_src, ip_sport, ip_dst, ip_dport)]
                    # Finding and retrieving stream Dictionaries, end
                        if tls_stream.client_encrypted_handshake_message:
                            tls_stream.client_encrypted_handshake_message = False
                            print('Find the TLS 1.3 client encrypted handshake message, not use it!')
                        else:
                            application_sequence = '[{0},{1}]:{2}'.format(pkt_num, ts, len(record.data))
                            application_sequence_to_divide_by_server_name = [pkt_num, ts, len(record.data)]
                            tls_stream.client_applications.append(application_sequence)
                            tls_stream.TLS_application_data_sequences.append(np.array([len(record.data), ts]))
                            tls_stream.client_application_sequence_to_divide_by_server_name.append(
                                application_sequence_to_divide_by_server_name)
                            # Put client_application_data message in the client_application_list,
                            # the purpose is to differentiate between ADUs
                            # application_sequence_for_list = '{0}      [{1}]'.format(len(record.data), pkt_num)
                            application_sequence_for_list = ['{0}'.format(ts), '{0}'.format(len(record.data))]
                            application_sequence_for_list_with_pkt_num = ['{0}'.format(ts), '[{0}]  {1}'.format(
                                pkt_num, len(record.data))]
                            if tls_stream.last_application_direction is None:
                                tls_stream.last_application_direction = 'client'
                                tls_stream.client_application_list.append(application_sequence_for_list_with_pkt_num)
                                tls_stream.temp_var_of_client_application_num += 1
                                # arrange_ADUs_in_order
                                tls_stream.current_ADU_pkt_num = pkt_num
                                l_client = [tls_stream.server_name, tls_stream.client_port, pkt_num, ts, ts, 'client:']
                                l_server = ['', '', '', '', '', 'server:']
                                l_client.append(len(record.data))
                                ADUs_dict[tls_stream.current_ADU_pkt_num] = [l_client, l_server]
                                ADU_nums += 1
                                # arrange_ADUs_in_order.append()
                            elif tls_stream.last_application_direction == 'client':
                                tls_stream.client_application_list.append(application_sequence_for_list)
                                tls_stream.temp_var_of_client_application_num += 1
                                # arrange_ADUs_in_order
                                l_client, l_server = ADUs_dict[tls_stream.current_ADU_pkt_num]
                                l_client[4] = ts  # update the ADU_end_time
                                l_client.append(len(record.data))
                                ADUs_dict[tls_stream.current_ADU_pkt_num] = [l_client, l_server]
                            elif tls_stream.last_application_direction == 'server':
                                # judge the blank of ADUs.
                                if tls_stream.temp_var_of_client_application_num >= \
                                        tls_stream.temp_var_of_server_application_num:
                                    for i in range(tls_stream.temp_var_of_client_application_num -
                                                   tls_stream.temp_var_of_server_application_num):
                                        tls_stream.server_application_list.append(['', ''])
                                else:
                                    for i in range(tls_stream.temp_var_of_server_application_num -
                                                   tls_stream.temp_var_of_client_application_num):
                                        tls_stream.client_application_list.append(['', ''])
                                tls_stream.client_application_list.append(['|', '|'])
                                tls_stream.server_application_list.append(['|', '|'])
                                tls_stream.client_application_list.append(application_sequence_for_list_with_pkt_num)
                                tls_stream.temp_var_of_client_application_num = 1
                                tls_stream.temp_var_of_server_application_num = 0
                                # arrange_ADUs_in_order
                                # l_client, l_server = ADUs_dict[tls_stream.current_ADU_pkt_num]
                                # arrange_ADUs_in_order[ADU_num_current] = [l_client, l_server]
                                tls_stream.current_ADU_pkt_num = pkt_num
                                l_client = [tls_stream.server_name, tls_stream.client_port, pkt_num, ts, ts, 'client:']
                                l_server = ['', '', '', '', '', 'server:']
                                l_client.append(len(record.data))
                                ADUs_dict[tls_stream.current_ADU_pkt_num] = [l_client, l_server]
                                ADU_nums += 1

                            tls_stream.last_application_direction = 'client'

            else:
                print('This connection({0}) has error!'.format(connection))
        record_num += 1
        # sys.stdout.flush()


def parse_tls_handshake(ip, data, ts):
    """
    Parses TLS Handshake message contained in data according to their type.
    Input:
    'ip': Current full IP protocol package.
    'data': TLS Record data field —— TLS handshake content.
    'ts': Time stamp of current message.
    """
    global encrypted_streams
    global ssl_servers_certs
    global TLSStream_dict
    connection = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip.src),
                                          ip.data.sport,
                                          socket.inet_ntoa(ip.dst),
                                          ip.data.dport)
    if connection in encrypted_streams:
        print('[+] Encrypted handshake message between {0}'.format(connection))
        return
    else:
        try:
            handshake_type = ord(data[:1])
            print('First 10 bytes {0}'.format(hexlify(data[:10])))
            if handshake_type == 4:
                print('[#] New Session Ticket is not implemented yet')
                return
            else:
                handshake = dpkt.ssl.TLSHandshake(data)
        except dpkt.ssl.SSL3Exception as exception:
            print('exception while parsing TLS handshake record: {0}'.format(exception))
            return
        except dpkt.dpkt.NeedData as exception:
            print('exception while parsing TLS handshake record: {0}'.format(exception))
            return
    client = '{0}:{1}'.format(socket.inet_ntoa(ip.src), ip.data.sport)
    server = '{0}:{1}'.format(socket.inet_ntoa(ip.dst), ip.data.dport)
    connection = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip.src),
                                          ip.data.sport,
                                          socket.inet_ntoa(ip.dst),
                                          ip.data.dport)
    global flow_direction  # only using in parse_extension()
    global flow_directions  # using in more ways
    if handshake.type == 0:
        print('<-  Hello Request {0} <- {1}'.format(client, server))
    if handshake.type == 1:
        print(' -> ClientHello {0} -> {1}'.format(client, server))
        # 新添加
        flow_direction = 'client2server'
        flow_directions[connection] = 'client2server'

        # The purpose is to further parse the extended fields,
        # Otherwise, for example,"supported version" field cannot be distinguished normally.
        parse_client_hello(ip, handshake)
    if handshake.type == 2:
        print('<-  ServerHello {1} <- {0}'.format(client, server))
        flow_direction = 'server2client'
        flow_directions[connection] = 'server2client'
        parse_server_hello(ip, handshake.data)
    if handshake.type == 11:
        ip_src, ip_sport, ip_dst, ip_dport = get_dict_key(ip)
        print('<-  Certificate {0} <- {1}'.format(client, server))
        handshake_data_cert = handshake.data
        assert isinstance(handshake_data_cert, dpkt.ssl.TLSCertificate)
        certs = []
        # Finding and retrieving stream Dictionaries, begin
        if (ip.data.sport == 443 or ip.data.dport == 443) and (
                ip_src, ip_sport, ip_dst, ip_dport) in TLSStream_dict.keys():
            tls_stream = TLSStream_dict[
                (ip_src, ip_sport, ip_dst, ip_dport)]
        # Finding and retrieving stream Dictionaries, end
            tls_stream.certs_true_len = len(handshake_data_cert)
            tls_stream.TLS_application_data_sequences.append([-len(handshake_data_cert), ts])
            TLSStream_dict[(ip_src, ip_sport, ip_dst, ip_dport)] = tls_stream
        print('Server certificates length is {0}'.format(len(handshake_data_cert)))
        for i in range(len(handshake_data_cert.certificates)):
            print('handshake certificates[{0}]:'.format(i), handshake_data_cert.certificates[i])
            try:
                # Calculate SHA of certificate
                cert = x509.Certificate.load(handshake_data_cert.certificates[i])
                sha = cert.sha256_fingerprint.replace(" ", "")
                print(sha)
                certs.append(sha)
            except Exception:
                print('exception while parsing certs into sha256 value: {0}'.format(Exception))
                continue
        # Finding and retrieving stream Dictionaries, begin
        if (ip.data.sport == 443 or ip.data.dport == 443) and (
                ip_src, ip_sport, ip_dst, ip_dport) in TLSStream_dict.keys():
            tls_stream = TLSStream_dict[
                (ip_src, ip_sport, ip_dst, ip_dport)]
        # Finding and retrieving stream Dictionaries, end
            tls_stream.certs_in_sha256 = certs
            TLSStream_dict[
                (ip_src, ip_sport, ip_dst, ip_dport)] = tls_stream
        ssl_servers_certs[connection] = certs
        print("certs all here:", certs)
    if handshake.type == 12:
        print('<-  ServerKeyExchange {1} <- {0}'.format(server, client))
    if handshake.type == 13:
        print('<-  CertificateRequest {1} <- {0}'.format(client, server))
    if handshake.type == 14:
        print('<-  ServerHelloDone {1} <- {0}'.format(client, server))
    if handshake.type == 15:
        print(' -> CertificateVerify {0} -> {1}'.format(client, server))
    if handshake.type == 16:
        print(' -> ClientKeyExchange {0} -> {1}'.format(client, server))
    if handshake.type == 20:
        print(' -> Finished {0} -> {1}'.format(client, server))


def unpacker(type_string, packet):
    """
    Input:
    'type_string': The type tag to which the field currently being resolved belongs.
    'packet': All currently unresolved byte stream data.

    Returns: The data parsed by the current field, and the raw byte stream data that has not been parsed later.
    """
    length = 0
    if type_string.endswith('H'):
        length = 2
    if type_string.endswith('B'):
        length = 1
    if type_string.endswith('P'):  # 2 bytes for the length of the string
        length, packet = unpacker('H', packet)
        type_string = '{0}s'.format(length)
    if type_string.endswith('p'):  # 1 byte for the length of the string
        length, packet = unpacker('B', packet)
        type_string = '{0}s'.format(length)
    data = struct.unpack('!' + type_string, packet[:length])[0]
    if type_string.endswith('s'):
        # data = ''.join(data)
        data = data
    return data, packet[length:]


def parse_server_hello(ip, handshake):
    """
    Parses server hello handshake.
    Input:
    'ip': Current full IP protocol package.
    'handshake': The TLS record content type is handshake(22), and handshake type is Server Hello(2).
    """
    global TLSStream_dict
    payload = handshake.data
    session_id, payload = unpacker('p', payload)
    cipher_suite, payload = unpacker('H', payload)
    ip_src, ip_sport, ip_dst, ip_dport = get_dict_key(ip)
    # Finding and retrieving stream Dictionaries, begin
    if (ip.data.sport == 443 or ip.data.dport == 443) and (
            ip_src, ip_sport, ip_dst, ip_dport) in TLSStream_dict.keys():
        tls_stream = TLSStream_dict[(ip_src, ip_sport, ip_dst, ip_dport)]
        # Finding and retrieving stream Dictionaries, end
        tls_stream.has_server_hello = True
        tls_stream.server_cipher_suites = pretty_name('cipher_suites', cipher_suite)
        TLSStream_dict[
            (ip_src, ip_sport, ip_dst, ip_dport)] = tls_stream
    print('[*]   Cipher: {0}'.format(pretty_name('cipher_suites', cipher_suite)))
    compression, payload = unpacker('B', payload)
    print('[*]   Compression: {0}'.format(pretty_name('compression_methods', compression)))
    extensions = parse_extensions(ip, payload)
    if extensions is None:
        return
    for extension in extensions:
        print('      {0}'.format(extension))


def parse_client_hello(ip, handshake):
    """
        Parses client hello handshake.
        Input:
        'ip': Current full IP protocol package.
        'handshake': The TLS record content type is handshake(22), and handshake type is Client Hello(1).
    """
    global TLSStream_dict
    hello = handshake.data
    payload = handshake.data.data
    session_id, payload = unpacker('p', payload)
    cipher_suites, pretty_cipher_suites = parse_extension(ip, payload, 'cipher_suites')
    ip_src, ip_sport, ip_dst, ip_dport = get_dict_key(ip)
    # Finding and retrieving stream Dictionaries, begin
    if (ip.data.sport == 443 or ip.data.dport == 443) and (
            ip_src, ip_sport, ip_dst, ip_dport) in TLSStream_dict.keys():
        tls_stream = TLSStream_dict[(ip_src, ip_sport, ip_dst, ip_dport)]
        # Finding and retrieving stream Dictionaries, end
        tls_stream.has_client_hello = True
        tls_stream.client_ip = socket.inet_ntoa(ip.src)
        tls_stream.client_port = ip.data.sport
        tls_stream.server_ip = socket.inet_ntoa(ip.dst)
        tls_stream.server_port = ip.data.dport
        tls_stream.client_hello_version = dpkt.ssl.ssl3_versions_str[hello.version]
        tls_stream.client_ciphers = pretty_cipher_suites
        TLSStream_dict[(ip_src, ip_sport, ip_dst, ip_dport)] = tls_stream
    print('TLS Record Layer Length: {0}'.format(len(handshake)))
    print('Client Hello Version: {0}'.format(dpkt.ssl.ssl3_versions_str[hello.version]))
    print('Client Hello Length: {0}'.format(len(hello)))
    print('Session ID: {0}'.format(hexlify(session_id)))
    print('[*]   Ciphers: {0}'.format(pretty_cipher_suites))
    # consume 2 bytes for each cipher suite plus 2 length bytes
    payload = payload[(len(cipher_suites) * 2) + 2:]
    compressions, pretty_compressions = parse_extension(ip, payload, 'compression_methods')
    print('[*]   Compression methods: {0}'.format(pretty_compressions))
    # consume 1 byte for each compression method plus 1 length byte
    payload = payload[len(compressions) + 1:]
    extensions = parse_extensions(ip, payload)
    for extension in extensions:
        print('      {0}'.format(extension))


def parse_extensions(ip, payload):
    """
    Parse data as one or more TLS extensions.
    Input:
    'ip': Current full IP protocol package.
    'payload': Extension payload.
    """
    extensions = []
    if len(payload) <= 0:
        return
    print('[*]   Extensions:')
    extensions_len, payload = unpacker('H', payload)
    print('Extensions Length: {0}'.format(extensions_len))
    while len(payload) > 0:
        extension = Extension(ip, payload)
        extensions.append(extension)
        # consume 2 bytes for type and 2 bytes for length
        payload = payload[extension.__length__() + 4:]
    return extensions


def parse_alert_message(connection, payload):
    """
    Parses a TLS alert message.
    Input:
    'connection': The stream connection to which the current TCP message belongs.
    'payload': The data of TLS Record.
    """
    global encrypted_streams
    print(hexlify(payload))
    if connection in encrypted_streams:
        print('[+] Encrypted TLS Alert message between {0}'.format(connection))
        # presume the alert message ended the encryption
        encrypted_streams.remove(connection)
    else:
        alert_level, payload = unpacker('B', payload)
        alert_description, payload = unpacker('B', payload)
        print('[+] TLS Alert message between {0}: {1} {2}'.
              format(connection, pretty_name('alert_level', alert_level),
                     pretty_name('alert_description', alert_description)))


def parse_extension(ip, payload, type_name):
    """
    Parses an extension based on the type_name.
    Input:
    'ip': Current full IP protocol package.
    'payload': The data of Extension.
    'type_name': The type name of the Extension field.
    Returns:
    An array of raw values as well as an array of prettified values.
    """
    global TLSStream_dict
    global flow_direction
    entries = []
    pretty_entries = []
    format_list_length = 'H'
    format_entry = 'B'
    list_length = 0
    ip_src, ip_sport, ip_dst, ip_dport = get_dict_key(ip)
    # Finding and retrieving stream Dictionaries, begin
    if (ip.data.sport != 443 and ip.data.dport != 443) or (
            ip_src, ip_sport, ip_dst, ip_dport) not in TLSStream_dict.keys():
        return entries, pretty_entries
    tls_stream = TLSStream_dict[(ip_src, ip_sport, ip_dst, ip_dport)]
    # Finding and retrieving stream Dictionaries, end
    if type_name == 'elliptic_curves':
        format_list_length = 'H'
        format_entry = 'H'
    if type_name == 'ec_point_formats':
        format_list_length = 'B'
    if type_name == 'renegotiation_info':
        format_list_length = 'B'
        if len(payload) == 1 and payload[0] == b'0x00':
            print('type {0}, list type is {1}, number of entries is 0'.format(type_name, format_list_length))
            pretty_entries.append('Renegotiation info extension length: 0')
            return entries, pretty_entries
    if type_name == 'compression_methods':
        format_list_length = 'B'
        format_entry = 'B'
    if type_name == 'psk_key_exchange_modes':
        format_list_length = 'B'
        format_entry = 'B'
    if type_name == 'supported_versions':
        if flow_direction == 'client2server':
            format_list_length = 'B'
            format_entry = 'H'
            print('type {0}, flow direction is {1}, client offered the list of TLS version it supported'.
                  format(type_name, flow_direction))
        elif flow_direction == 'server2client':
            format_entry = 'H'
            entry, payload = unpacker(format_entry, payload)
            entries.append(entry)
            pretty_entries.append('{0}'.format(pretty_name('tls_version', entry)))
            try:
                tls_stream.server_hello_version = pretty_name('tls_version', entry)
                if pretty_name('tls_version', entry) == 'TLS 1.3':
                    tls_stream.certs_len_calculate_flag = True
                    # The part of handshake information and certificate information of
                    # the Server Hello in TLS1.3 are sent out by application_data
                    tls_stream.client_encrypted_handshake_message = True
                    # The encrypted_handshake_message of the Client Hello in TLS1.3 are sent out by application_data
            except NameError:
                print('This packet not in a whole tls stream')
            print('type {0}, flow direction is {1}, server select one TLS version'.
                  format(type_name, flow_direction))
            return entries, pretty_entries
    if type_name == 'key_share':
        if flow_direction == 'client2server':
            client_key_share_length, payload = unpacker('H', payload)
            pretty_entries.append('client key share length:{0}------->'.format(client_key_share_length))
        key_share_num = 0
        while len(payload) > 0:
            key_share_num += 1
            group, payload = unpacker('H', payload)
            if len(payload) <= 0:
                continue
            key_exchange_length, payload = unpacker('H', payload)
            type_string = '{0}s'.format(key_exchange_length)
            key_exchange = struct.unpack('!' + type_string, payload[:key_exchange_length])[0]
            # key_exchange = payload[:key_exchange_length]
            entries.append(str(key_exchange))
            pretty_entries.append('group:{0} , Key Exchange Length:{1} , Key Exchange:{2};'.format(
                pretty_name('supported_groups', group), key_exchange_length, str(key_exchange)))
            payload = payload[key_exchange_length:]
        print('type {0}, list type is H, number of entries is {1}'.format(type_name, key_share_num))
        return entries, pretty_entries
    if type_name == 'heartbeat':
        format_list_length = 'B'
        format_entry = 'B'
    if type_name == 'next_protocol_negotiation':
        format_entry = 'p'
    else:
        if len(payload) > 1:  # contents are a list
            list_length, payload = unpacker(format_list_length, payload)
    print('type {0}, list type is {1}, number of entries is {2}'.format(type_name, format_list_length, list_length))
    if type_name == 'status_request' or type_name == 'status_request_v2':
        _type, payload = unpacker('B', payload)
        format_entry = 'H'
    if type_name == 'padding':
        return payload, hexlify(payload)
    if type_name == 'SessionTicket_TLS':
        return payload, hexlify(payload)
    if type_name == 'cipher_suites':
        format_entry = 'H'
    if type_name == 'supported_groups':
        format_entry = 'H'
    if type_name == 'signature_algorithms':
        format_entry = 'H'
    if list_length:
        payload = payload[:list_length]
    while len(payload) > 0:
        if type_name == 'server_name':
            _type, payload = unpacker('B', payload)
            format_entry = 'P'
        if type_name == 'application_layer_protocol_negotiation':
            format_entry = 'p'
        entry, payload = unpacker(format_entry, payload)
        entries.append(entry)
        # Write in dict()
        if type_name == 'server_name':
            try:
                tls_stream.server_name = str(entry, "utf-8")
            except NameError:
                print('This packet not in a whole tls stream')
        if type_name == 'application_layer_protocol_negotiation':
            if flow_direction == 'client2server':
                tls_stream.client_application_layer_protocol_negotiation.append(entry)
            elif flow_direction == 'server2client':
                tls_stream.server_application_layer_protocol_negotiation.append(entry)
        if type_name == 'signature_algorithms':
            # if entry > 2048:  # big than 0x0800, new signature_algorithms
            pretty_entries.append('{0}'.format(pretty_name('signature_algorithm', entry)))
            #  ######### do not use it now.
            # else:
            #     pretty_entries.append('{0}-{1}'.
            #                           format(pretty_name
            #                                  ('signature_algorithms_hash',
            #                                   entry >> 8),
            #                                  pretty_name('signature_algorithms_signature',
            #                                              entry % 256)))
        elif type_name == 'supported_versions' and flow_direction == 'client2server':
            pretty_entries.append('{0}'.format(pretty_name('tls_version', entry)))
        else:
            if format_entry.lower() == 'p':
                pretty_entries.append(entry)
            else:
                pretty_entries.append(pretty_name(type_name, entry))
    return entries, pretty_entries


def pretty_name(name_type, name_value):
    """
    Input:
    'name_type': The name of the field type.
    'name_value': Meaning of field value.
    Returns:
    The pretty name for type name_type.
    """
    if name_type in PRETTY_NAMES:
        if name_value in PRETTY_NAMES[name_type]:
            name_value = PRETTY_NAMES[name_type][name_value]
        else:
            name_value = '{0}: unknown value {1}'.format(name_value, name_type)
    else:
        name_value = 'unknown type: {0}'.format(name_type)
    return name_value


def clean_all_param():
    """Used to clear global variables before each new pcap file is read."""
    global stream_buffer
    stream_buffer = {}
    global encrypted_streams
    encrypted_streams = []
    global flow_directions
    flow_directions = {}
    global flow_direction
    flow_direction = None
    global ssl_servers_certs
    ssl_servers_certs = {}
    global TLSStream_dict
    TLSStream_dict = dict()
    # global arrange_ADUs_in_order
    # arrange_ADUs_in_order = {}
    global ADUs_dict
    ADUs_dict = dict()
    global ADU_nums
    ADU_nums = 0
    global tcp_stream_dict
    tcp_stream_dict = dict()


def read_file(filename):
    """
        Input:
        'filename': Path name of pcap file to be processed.
        """
    try:
        global TLSStream_dict
        TLSStream_dict = dict()
        with open(filename, 'rb') as f:
            capture = dpkt.pcap.Reader(f)
            i = 1
            first_timestamp = 0
            for timestamp, packet in capture:
                # if i>40:
                #     return
                if i == 1:
                    first_timestamp = timestamp
                print("Number ", i, "th packet & timestamp is ", timestamp-first_timestamp)
                try:
                    analyze_packet(timestamp-first_timestamp, i, packet)
                except dpkt.dpkt.NeedData:
                    i += 1
                    continue
                i += 1

    except IOError:
        print('could not parse {0}'.format(filename))


def sni_simplify(sni):  # 去掉首部的‘www.’以及尾部的‘.com’
    if len(sni) > 4 and sni[:4] == "www.":
        sni = sni[4:]
    if len(sni) > 4 and sni[-4:] == ".com":
        sni = sni[:-4]
    return sni


def main():
    """
    Main program loop.

    Input:
    'filepath'：The folder which need to deal,this filepath has many pcap files.
    'filter_sni_file'：Lengths and times sequence-data in total_file, will only contains these sni-names.Other sni will
                    be filtered.
    'merge_sni_file'：The SNI in this file will be merged and replaced with another representation, mainly used to merge
                    some synonymous SNI.

    Output:
    'total_file'：Lengths and times sequence-data which will be produced.
    'app_sni_file': The SNI information of all valid TLS streams in each pcap package is listed and extracted into the
                    file.

    -----------Notice that---------
    1.Each pcap generates a CSV file with the same name, containing most of the useful information in pcap.

    2.In filepath,a folder will be generated, which contains the files with the same name divided by SNI. It contains
                all the flow sequences information under the same SNI.

    3.The output CSV file——total_file will be used to generate the input data of the LSTM/GRU deep learning model,
    but before that, we need to use the 'SNI_to_flag' module to generate TLS stream label information.

    """

    global TLSStream_dict
    global ADUs_dict
    global application_list_by_server_name
    app_name = 'Google'
    filepath = 'F:/topic3-家族应用识别/data/Google应用/Google/'
    pathDir = os.listdir(filepath)
    pathDir.sort()
    total_file = 'F:/topic3-家族应用识别/data/google_and_apple_all.csv'
    app_sni_file = 'F:/topic3-家族应用识别/data/google_apple_app_sni.csv'  # 原始SNI标签提取，仅在特征分析阶段使用
    filter_sni_file = 'F:/topic3-家族应用识别/data/处理规则/SNI_filter_all.csv'
    merge_sni_file = 'F:/topic3-家族应用识别/data/处理规则/SNI_merge_same.csv'
# 过滤特定SNI,读取数据 begin
    filter_sni_dict = dict()
    try:
        with open(filter_sni_file, 'r+',
                  newline='') as filter_sni_f:
            filter_sni_reader = csv.reader(filter_sni_f)
            for filter_sni_row in filter_sni_reader:
                if filter_sni_row[0] not in filter_sni_dict.keys():
                    filter_sni_dict[filter_sni_row[0]] = 0
    except Exception:
        pass
# 过滤特定SNI，读取数据 end

# 合并相似的SNI，读取数据 begin
    merge_sni_dict = dict()
    try:
        with open(merge_sni_file, 'r+',
                  newline='') as merge_sni_f:
            merge_sni_reader = csv.reader(merge_sni_f)
            for merge_sni_row in merge_sni_reader:
                if merge_sni_row[0] not in merge_sni_dict.keys():
                    merge_sni_dict[merge_sni_row[0]] = merge_sni_row[1]
    except Exception:
        pass
# 合并相似的SNI，读取数据 end
    file_num = 1  # 文件序号
    with open(total_file, 'a+', newline='') as tf, open(app_sni_file, 'a+', newline='') as af:
        total_writer = csv.writer(tf, dialect="excel")  # 流序列文件total_file
        af_writer = csv.writer(af, dialect="excel")  # 应用-流名文件app_sni_file
        for Dir in pathDir:
            if '.csv' in str(Dir) or '.ADUs' in str(Dir):
                continue
            if '.pcap' not in str(Dir) and '.pcapng' not in str(Dir):
                continue
            files = os.path.join('%s%s' % (filepath, Dir))
            print(file_num, "号文件：", files)
            writingfile = os.path.join('%s%s' % (files, '.csv'))  # 在对应的pcap文件目录下生成同名csv文件，以.csv为后缀
            clean_all_param()
            read_file(files)
            flow_num = 1
            curr_sni_list = list()
            curr_sni_list.append(app_name)
            with open(writingfile, "w", newline="") as f:
                csvwriter = csv.writer(f, dialect="excel")
                # Title
                if flow_num == 1:
                    csvwriter.writerow(
                        ['client_ip', 'server_ip', 'client_port', 'server_port', 'server_name', 'start_time',
                         'fin_time', 'end_time', 'first_packet_num', 'total_tcp_flow_bytes', 'total_tls_flow_bytes',
                         'certs_in_sha256', 'certs_true_len', 'certs_len_calculate', 'server_cipher_suites',
                         'client_hello_version', 'server_hello_version', 'client_ciphers', 'TLSFlows_client_to_server',
                         'TLSFlows_server_to_client', 'TLSFlows_both_c2s_and_s2c', 'client_applications',
                         'server_applications',
                         ])
                # Write data to each line of csv file.
                # 在每个pcap包生成的同名csv文件中记录有效的TLS流信息
                for tls_stream in TLSStream_dict.values():
                    if tls_stream.has_client_hello and tls_stream.has_server_hello and tls_stream.valid:
                        csvwriter.writerow([
                            tls_stream.client_ip,
                            tls_stream.server_ip,
                            tls_stream.client_port,
                            tls_stream.server_port,
                            tls_stream.server_name,
                            tls_stream.start_time,
                            tls_stream.fin_time,
                            tls_stream.end_time,
                            tls_stream.first_packet_num,
                            tls_stream.total_tcp_flow_bytes,
                            tls_stream.total_tls_flow_bytes,
                            tls_stream.certs_in_sha256,
                            tls_stream.certs_true_len,
                            tls_stream.certs_len_calculate,
                            tls_stream.server_cipher_suites,
                            tls_stream.client_hello_version,
                            tls_stream.server_hello_version,
                            tls_stream.client_ciphers,
                            tls_stream.TLSFlows_client_to_server,  # 只提取change_cipher_spec之后含application_data的TCP报文长度
                            tls_stream.TLSFlows_server_to_client,
                            tls_stream.TLSFlows_both_c2s_and_s2c,
                            tls_stream.client_applications,
                            tls_stream.server_applications
                        ])
                        # 如果server name存在，记录当前server name在pcap文件中的出现次数
                        if len(tls_stream.server_name):
                            if tls_stream.server_name in filter_sni_dict.keys():
                                curr_sni_list.append(tls_stream.server_name)  # 将出现过的SNI保存下来，将输出至app_sni_file文件

                        # #####改动2（提取长度和时间序列——>二维） total_file... extracting the SNI and sequence of time and length
                        # 在total_file文件中记录每条有效的TLS流序列
                        if len(tls_stream.TLS_application_data_sequences) > 1 and len(tls_stream.server_name):
                            # 过滤掉只有证书无其他信息的流，或者SNI不明的流
                            if tls_stream.server_name in filter_sni_dict.keys():
                                total_row = tls_stream.TLS_application_data_sequences
                                len_sequence = list()
                                time_sequence = list()
                                temp_sni = None
                                if tls_stream.server_name in merge_sni_dict.keys():  # 若SNI属于某一组，替换为SNI组名
                                    temp_sni = sni_simplify(merge_sni_dict[tls_stream.server_name])
                                else:  # 否则直接输出原SNI名
                                    temp_sni = sni_simplify(tls_stream.server_name)
                                len_sequence.append(temp_sni)
                                app_flag_in_stream = app_name + '-' + str(file_num)  # 输出此TLS流所属的应用标签，以及对应的pcap包序号
                                time_sequence.append(app_flag_in_stream)
                                last = total_row[0][1]  # 保存第一个时间戳
                                # # 计算相对时间间隔（与前一个相比）
                                # for row in total_row:
                                #     curr = row[1]
                                #     row[1] -= last
                                #     last = curr   #计算相对时间
                                #     len_sequence.append(row[0])
                                #     time_sequence.append(row[1])

                                # 计算相对时间（与第一个相比）
                                max_seq_len = 0  # total_file中提取的最大序列长为45，超过45就截断
                                for row in total_row:
                                    if max_seq_len > 45:
                                        break
                                    row[1] -= last
                                    len_sequence.append(row[0])
                                    time_sequence.append(row[1])
                                    max_seq_len += 1
                                ######################
                                if len(len_sequence) > 4:
                                    # 大于4的序列才输出
                                    total_writer.writerow(len_sequence)
                                    total_writer.writerow(time_sequence)
                        # #####改动2  end

                        #  ######## extract and divide the APP-data and ts of each flows
                        #  提取每条TLS流信息，按SNI进行分类。对整个目录下所有pcap文件进行统计
                        #  此部分代码将数据统一输出至‘按域名划分’文件夹下，每个文件以SNI命名，包含所有相同域名的TLS流信息
                        if len(tls_stream.server_name) and (len(tls_stream.client_application_sequence_to_divide_by_server_name)
                                                            or len(tls_stream.server_application_sequence_to_divide_by_server_name)):
                            #  #server_name必须存在，并且client->server或者server->client方向必须有数据
                            if tls_stream.server_name not in application_list_by_server_name.keys():
                                application_list_by_server_name[tls_stream.server_name] = []
                            client_app_by_server_name = []
                            client_ts_by_server_name = []
                            server_app_by_server_name = []
                            server_ts_by_server_name = []
                            for client_inform in tls_stream.client_application_sequence_to_divide_by_server_name:
                                # 提取client->server方向上的时间戳和application data数据长度
                                client_ts_by_server_name.append(client_inform[1])
                                client_app_by_server_name.append(client_inform[2])
                            for server_inform in tls_stream.server_application_sequence_to_divide_by_server_name:
                                # 提取server->client方向上的时间戳和application data数据长度
                                server_ts_by_server_name.append(server_inform[1])
                                server_app_by_server_name.append(server_inform[2])
                            list_of_app = [client_ts_by_server_name, client_app_by_server_name,
                                           server_ts_by_server_name, server_app_by_server_name]
                            application_list_by_server_name[tls_stream.server_name].append(list_of_app)

                        #  ######## display APP-data and ts of each flow
                        #  在每个pcap包生成的同名csv文件中记录有效的TLS流长度和时间序列，这个序列中以'|'划分了突发数据
                        csvwriter.writerow('')
                        client_ts_list = []
                        client_app_list = []
                        server_ts_list = []
                        server_app_list = []
                        for client_application in tls_stream.client_application_list:
                            client_ts_list.append(client_application[0])
                            client_app_list.append(client_application[1])
                        for server_application in tls_stream.server_application_list:
                            server_ts_list.append(server_application[0])
                            server_app_list.append(server_application[1])
                        csvwriter.writerow(client_ts_list)
                        csvwriter.writerow(client_app_list)
                        csvwriter.writerow('')
                        csvwriter.writerow(server_ts_list)
                        csvwriter.writerow(server_app_list)
                        csvwriter.writerow('')
                        flow_num += 1
                # 在每个pcap包生成的同名csv文件中记录整个pcap包中的数据突发
                csvwriter.writerow(['*********arrange_ADUs_in_time_order***********'])
                csvwriter.writerow(['Server Name', 'Client Port', 'first pkt number', 'begin_time', 'end_time'])
                for ADU in ADUs_dict.values():
                    [l_client, l_server] = ADU
                    csvwriter.writerow(l_client)
                    csvwriter.writerow(l_server)
                    csvwriter.writerow('')
            # 将每个pcap包的应用标签、出现的SNI名记录到app_sni_file文件中
            af_writer.writerow(curr_sni_list)  # app_sni_file csv文件更新行
            file_num += 1
    #  ######## divide data in each SNI domain.
    #  对整个pcap文件目录下的所有pcap文件，统计所有出现过的SNI，以及属于该SNI的TLS流长度与时间序列信息，输出至'按域名划分'文件夹下，以SNI名生成对应CSV文件
    if len(application_list_by_server_name):
        file_domain_name = os.path.join('%s%s' % (filepath, '按域名划分'))
        if not os.path.exists(file_domain_name):
            os.mkdir(file_domain_name)
        file_domain_name = os.path.join('%s%s' % (filepath, '按域名划分/'))
        for servername in application_list_by_server_name.keys():  # 先找每个SNI
            file_sni = os.path.join('%s%s%s' % (file_domain_name, servername, '.csv'))
            with open(file_sni, "w", newline="") as s:
                csvwriter_sni_app = csv.writer(s, dialect="excel")
                for list_of_app in application_list_by_server_name[servername]:
                    csvwriter_sni_app.writerow(list_of_app[0])
                    csvwriter_sni_app.writerow(list_of_app[1])
                    csvwriter_sni_app.writerow(list_of_app[2])
                    csvwriter_sni_app.writerow(list_of_app[3])
                    csvwriter_sni_app.writerow('')
    #  ########


if __name__ == "__main__":
    main()
