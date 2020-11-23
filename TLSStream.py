#!/usr/bin/env python
# coding=utf-8


class TLSStream(object):

    def __init__(self, src, src_port, dst, dst_port, timestamp, first_packet_num):
        self.src = src
        self.src_port = src_port
        self.dst = dst
        self.dst_port =dst_port
        self.client_ip = src
        self.server_ip = dst
        self.client_port = src_port
        self.server_port = dst_port
        self.start_time = timestamp
        self.end_time = timestamp
        self.fin_time = 0
        self.has_client_hello = False
        self.has_server_hello = False
        self.valid = True
        self.first_packet_num = first_packet_num
        self.total_tcp_flow_bytes = 0
        self.total_tls_flow_bytes = 0
        self.certs_len_calculate_flag = False
        self.client_encrypted_handshake_message = False
        self.certs_in_sha256 = {}
        self.certs_len_calculate = 0
        self.certs_true_len = 0
        self.server_name = []
        self.client_application_layer_protocol_negotiation = []
        self.server_application_layer_protocol_negotiation = []
        self.client_ciper_change_spec_flag = False
        self.server_ciper_change_spec_flag = False
        self.client_application_begin_pkt_number = 0
        self.server_application_begin_pkt_number = 0
        self.client_application_begin_time = 0
        self.server_application_begin_time = 0
        self.client_packet_list = {}
        self.server_packet_list = {}
        self.stream_buffer = 0
        self.server_cipher_suites = []
        self.client_hello_version = []
        self.server_hello_version = []
        self.client_ciphers = {}
        self.maybe_cert_len = []
        self.TLSFlows_client_to_server = []
        self.TLSFlows_server_to_client = []
        self.TLSFlows_both_c2s_and_s2c = []
        self.client_applications = []
        self.server_applications = []
        self.client_application_sequence_to_divide_by_server_name = []
        self.server_application_sequence_to_divide_by_server_name = []
        self.application_nums = 0
        self.client_application_list = [['client_ts', '*client_app*']]   # writing in csv client_list
        self.server_application_list = [['server_ts', '*server_app*']]   # writing in csv server_list
        self.server_applications = []
        self.last_application_direction = None
        self.temp_var_of_client_application_num = 0
        self.temp_var_of_server_application_num = 0
        self.current_ADU_pkt_num = None  # for the first packet number of each ADU of this TLS stream
        self.TLS_application_data_sequences = []
        self.stream_error_nums = 0

    def __len__(self):
        return self.total_tls_flow_bytes

    @property
    def duration(self):
        return self.end_time - self.start_time
