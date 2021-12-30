from scapy.all import IP, TCP, UDP
from statistics import stdev

class Flow:
    def __init__(self, packet):
        self.ip_src = packet[IP].src
        self.ip_dst = packet[IP].dst

        if TCP in packet:
            self.port_src = packet[TCP].sport
            self.port_dst = packet[TCP].dport
            
            self.fin_flag_cnt = 1 if "F" in packet[TCP].flags else 0
            self.syn_flag_cnt = 1 if "S" in packet[TCP].flags else 0
            self.rst_flag_cnt = 1 if "R" in packet[TCP].flags else 0
            self.psh_flag_cnt = 1 if "P" in packet[TCP].flags else 0
            self.ack_flag_cnt = 1 if "A" in packet[TCP].flags else 0
            self.urg_flag_cnt = 1 if "U" in packet[TCP].flags else 0
            self.ece_flag_cnt = 1 if "E" in packet[TCP].flags else 0
            self.cwr_flag_cnt = 1 if "C" in packet[TCP].flags else 0

            self.fwd_init_window = packet[TCP].window
            self.bwd_init_window = 0
        else:
            self.port_src = packet[UDP].sport
            self.port_dst = packet[UDP].dport

            self.fin_flag_cnt = 0
            self.syn_flag_cnt = 0
            self.rst_flag_cnt = 0
            self.psh_flag_cnt = 0
            self.ack_flag_cnt = 0
            self.urg_flag_cnt = 0
            self.ece_flag_cnt = 0
            self.cwr_flag_cnt = 0

            self.fwd_init_window = 0
            self.bwd_init_window = 0

        self.protocol = packet[IP].proto

        self.last_time = packet.time
        self.start_time = packet.time
        
        self.duration = 0
        self.flow_bytes_per_s = 0
        self.flow_pkt_per_s = 0
        self.fwd_pkt_per_s = 0
        self.bwd_pkt_per_s = 0

        self.tot_fwd_pkt = 1
        self.tot_bwd_pkt = 0

        self.fwd_pkt_len = [len(packet)]
        self.bwd_pkt_len = []

        self.flow_iat = []
        self.fwd_iat = []
        self.bwd_iat = []

        self.down_up_ratio = 0
        self.pkt_size_avg = len(packet)

        self.last_time_fwd = packet.time
        self.last_time_bwd = 0

        self.fwd_header_len = [packet.ihl*4]
        self.bwd_header_len = []
    
    def add_packet(self, packet, status):
        if TCP in packet:
            self.fin_flag_cnt = 1 if "F" in packet[TCP].flags else 0
            self.syn_flag_cnt = 1 if "S" in packet[TCP].flags else 0
            self.rst_flag_cnt = 1 if "R" in packet[TCP].flags else 0
            self.psh_flag_cnt = 1 if "P" in packet[TCP].flags else 0
            self.ack_flag_cnt = 1 if "A" in packet[TCP].flags else 0
            self.urg_flag_cnt = 1 if "U" in packet[TCP].flags else 0
            self.ece_flag_cnt = 1 if "E" in packet[TCP].flags else 0
            self.cwr_flag_cnt = 1 if "C" in packet[TCP].flags else 0
        else:
            self.fin_flag_cnt = 0
            self.syn_flag_cnt = 0
            self.rst_flag_cnt = 0
            self.psh_flag_cnt = 0
            self.ack_flag_cnt = 0
            self.urg_flag_cnt = 0
            self.ece_flag_cnt = 0
            self.cwr_flag_cnt = 0

        self.duration = packet.time - self.start_time
        self.flow_iat.append(packet.time - self.last_time)

        #self.pkt_size_avg = (sum(self.fwd_pkt_len) + sum(self.bwd_pkt_len)) / (self.tot_fwd_pkt + self.tot_bwd_pkt)

        if status == 1 or status == 4:
            self.tot_fwd_pkt += 1
            if TCP in packet: self.fwd_init_window = packet[TCP].window
            self.fwd_pkt_len.append(len(packet))
            self.fwd_iat.append(packet.time - self.last_time_fwd)
            self.last_time_fwd = packet.time
            self.fwd_header_len.append(packet.ihl*4)
        else:
            self.tot_bwd_pkt += 1
            if TCP in packet: self.bwd_init_window = packet[TCP].window
            self.bwd_pkt_len.append(len(packet))
            if self.last_time_bwd != 0:
                self.bwd_iat.append(packet.time - self.last_time_bwd)
            else:
                if TCP in packet:
                    self.bwd_init_window = packet.window
            self.last_time_bwd = packet.time
            self.bwd_header_len.append(packet.ihl*4)
        
        #self.down_up_ratio = self.tot_bwd_pkt / self.tot_fwd_pkt
        self.last_time = packet.time
    
    def extract_feature(self):
        feature = []

        feature.append(self.ip_src)
        feature.append(self.port_src)
        feature.append(self.ip_dst)
        feature.append(self.port_dst)

        feature.append(self.ack_flag_cnt)
        feature.append(self.ece_flag_cnt)
        feature.append(self.psh_flag_cnt)
        feature.append(self.rst_flag_cnt)
        feature.append(self.syn_flag_cnt)
        feature.append(self.urg_flag_cnt)
        feature.append(self.fin_flag_cnt)
        feature.append(self.cwr_flag_cnt)

        feature.append(self.fwd_init_window)
        feature.append(self.bwd_init_window)
        feature.append(self.protocol)
        feature.append(self.duration)

        try:
            #feature.append(self.flow_bytes_per_s)
            feature.append((sum(self.fwd_pkt_len) + sum(self.bwd_pkt_len)) / self.duration)     #flow_bytes_per_s
            #feature.append(self.flow_pkt_per_s)
            feature.append((self.tot_fwd_pkt + self.tot_bwd_pkt) / self.duration)               #flow_pkt_per_s
            #feature.append(self.fwd_pkt_per_s)
            feature.append(self.tot_fwd_pkt / self.duration)                                    #fwd_pkt_per_s
            #feature.append(self.bwd_pkt_per_s)
            feature.append(self.tot_bwd_pkt / self.duration)                                    #bwd_pkt_per_s
        except:
            feature.append(0)
            feature.append(0)
            feature.append(0)
            feature.append(0)
        
        feature.append(self.tot_fwd_pkt)
        feature.append(self.tot_bwd_pkt)

        feature.append(max(self.fwd_pkt_len))
        feature.append(min(self.fwd_pkt_len))
        feature.append(sum(self.fwd_pkt_len) / (self.tot_fwd_pkt))
        try:
            feature.append(stdev(self.fwd_pkt_len))
        except:
            feature.append(0)

        try:
            feature.append(max(self.bwd_pkt_len))
            feature.append(min(self.bwd_pkt_len))
            feature.append(sum(self.bwd_pkt_len) / (self.tot_bwd_pkt))
            try:
                feature.append(stdev(self.bwd_pkt_len))
            except:
                feature.append(0)
        except:
            feature.append(0)
            feature.append(0)
            feature.append(0)
            feature.append(0)

        try:
            feature.append(max(self.flow_iat))
            feature.append(min(self.flow_iat))
            try:
                feature.append(sum(self.flow_iat) / (self.tot_fwd_pkt + self.tot_bwd_pkt - 1))
            except:
                feature.append(0)
            try:
                feature.append(stdev(self.flow_iat))
            except:
                feature.append(0)
        except:
            feature.append(0)
            feature.append(0)
            feature.append(0)
            feature.append(0)

        try:
            feature.append(max(self.fwd_iat))
            feature.append(min(self.fwd_iat))
            try:
                feature.append(sum(self.fwd_iat) / (self.tot_fwd_pkt - 1))
            except:
                feature.append(0)
            try:
                feature.append(stdev(self.fwd_iat))
            except:
                feature.append(0)
        except:
            feature.append(0)
            feature.append(0)
            feature.append(0)
            feature.append(0)
        
        try:
            feature.append(max(self.bwd_iat))
            feature.append(min(self.bwd_iat))
            try:
                feature.append(sum(self.bwd_iat) / (self.tot_bwd_pkt - 1))
            except:
                feature.append(0)
            try:
                feature.append(stdev(self.bwd_iat))
            except:
                feature.append(0)
        except:
            feature.append(0)
            feature.append(0)
            feature.append(0)
            feature.append(0)
        
        #feature.append(self.down_up_ratio)                                  #down_up_ratio
        feature.append(self.tot_bwd_pkt/self.tot_fwd_pkt)
        #feature.append(self.pkt_size_avg)                                  #pkt_size_avg
        feature.append((sum(self.fwd_pkt_len) + sum(self.bwd_pkt_len)) / (self.tot_fwd_pkt + self.tot_bwd_pkt))

        try:
            feature.append(max(self.fwd_header_len))
            feature.append(min(self.fwd_header_len))
            feature.append(sum(self.fwd_header_len) / self.tot_fwd_pkt)
            try:
                feature.append(stdev(self.fwd_header_len))
            except:
                feature.append(0)
        except:
            feature.append(0)
            feature.append(0)
            feature.append(0)
            feature.append(0)

        try:
            feature.append(max(self.bwd_header_len))
            feature.append(min(self.bwd_header_len))
            try:
                feature.append(sum(self.bwd_header_len) / self.tot_bwd_pkt)
            except:
                feature.append(0)
            try:
                feature.append(stdev(self.bwd_header_len))
            except:
                feature.append(0)
        except:
            feature.append(0)
            feature.append(0)
            feature.append(0)
            feature.append(0)
        
        return feature
