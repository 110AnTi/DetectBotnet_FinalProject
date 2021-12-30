from scapy.all import sniff, IP, UDP, TCP
from flow import Flow
import csv
import joblib
import os
import ipwhois
import tkinter as tk

flows = {}
PCAP_FILE = "/home/hoanhtien/Documents/ISCX_Botnet-Training.pcap"
MODEL_FILE = "/home/hoanhtien/Documents/mod/model.sav"
DATASET_FILE = "bigFLows.csv"
clf = joblib.load(MODEL_FILE)

WHITE_LIST = ["192.168.91.180", "127.0.0.1", "192.168.91.2", "192.168.91.254"]
BLOCK_LIST = []
#FLOW_DICT = {}
IP_DICT = {}

count = 0


def print_dict(d):
    t = "\n\t"
    for i in d:
        if type(d[i]) is dict:
            t += print_dict(d[i]) + "\n\t"
        elif type(d[i]) is list:
            t += print_list(d[i]) + "\n\t"
        else:
            t += i + " : " + str(d[i]) + "\n\t"
    return t
def print_list(l):
    t = "\n\t"
    for i in l:
        if type(i) is dict:
            t += print_dict(i) + "\n"
        elif type(i) is list:
            t += print_list(i) + "\n"
        else:
            t += str(i) + "\n\t"
    return t

def format_ip_info(ip):
    info = "{0} flows are botnet\n {1} flows are normal\n {2}% IP {3} is a bot\n".format(IP_DICT[ip][0], IP_DICT[ip][1], IP_DICT[ip][2] * 100, ip)
    try:
        ip_info = ipwhois.IPWhois(ip).lookup_whois()

        for i in ip_info:
            info += i + " : "
            if type(ip_info[i]) is dict:
                info += print_dict(ip_info[i]) + "\n"
            elif type(ip_info[i]) is list:
                info += print_list(ip_info[i]) + "\n"
            else:
                info += str(ip_info[i]) + "\n"
    except ipwhois.exceptions.IPDefinedError:
        info += ip + " is ip private!"

    return info

def check_status(packet):
    if TCP in packet:
        if (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport) in flows:
            return 1
        elif (packet[IP].dst, packet[TCP].dport, packet[IP].src, packet[TCP].sport) in flows:
            return 2
        else:
            return 3
    else:
        if (packet[IP].src, packet[UDP].sport, packet[IP].dst, packet[UDP].dport) in flows:
            return 4
        elif (packet[IP].dst, packet[UDP].dport, packet[IP].src, packet[UDP].sport) in flows:
            return 5
        else:
            return 6

def create_new_flow(packet, key):
    flow = Flow(packet)
    flows[key] = flow

def update_flow(packet, key, status):
    flow = flows[key]
    flow.add_packet(packet, status)

def block(ip, root):
    BLOCK_SRC_COMMAND_INPUT = "sudo iptables -A INPUT -s {} -j DROP".format(ip)
    BLOCK_DST_COMMAND_INPUT = "sudo iptables -A INPUT -d {} -j DROP".format(ip)

    BLOCK_SRC_COMMAND_OUTPUT = "sudo iptables -A OUTPUT -s {} -j DROP".format(ip)
    BLOCK_DST_COMMAND_OUTPUT = "sudo iptables -A OUTPUT -d {} -j DROP".format(ip)

    BLOCK_SRC_COMMAND_FORWARD = "sudo iptables -A FORWARD -s {} -j DROP".format(ip)
    BLOCK_DST_COMMAND_FORWARD = "sudo iptables -A FORWARD -d {} -j DROP".format(ip)

    os.system(BLOCK_SRC_COMMAND_INPUT)
    os.system(BLOCK_DST_COMMAND_INPUT)

    os.system(BLOCK_SRC_COMMAND_OUTPUT)
    os.system(BLOCK_DST_COMMAND_OUTPUT)

    os.system(BLOCK_SRC_COMMAND_FORWARD)
    os.system(BLOCK_DST_COMMAND_FORWARD)

    del IP_DICT[ip]

    BLOCK_LIST.append(ip)
    root.destroy()

def block_prompt(ip):
    root = tk.Tk()
    root.wm_title("Block IP: " + ip + " ?")
    root.resizable(False, False)
    root.after(20000, lambda: root.destroy())
    t = tk.Text(root)
    t.insert(tk.END, format_ip_info(ip))
    t.configure(state="disabled")
    t.grid(column=0, row=0, sticky="nswe")

    frame = tk.Frame(root)
    frame.grid(column=0, row=1, sticky="nswe")

    b1 = tk.Button(frame, text="BLOCK", command=lambda : block(ip, root))
    b1.grid(column=0, row=0, sticky="nswe")

    b2 = tk.Button(frame, text="IGNORE", command=root.destroy)
    b2.grid(column=1, row=0, sticky="nswe")

    frame.columnconfigure(0, weight=1)
    frame.columnconfigure(1, weight=1)

    root.mainloop()

def evaluate_ip(ip, label):
    if ip in WHITE_LIST or ip in BLOCK_LIST: return

    if label == "BOTNET":
        if ip not in IP_DICT:
            IP_DICT[ip] = [1, 0, 1]
        else:
            IP_DICT[ip][0] += 1
    else:
        if ip not in IP_DICT:
            IP_DICT[ip] = [0, 1, 0]
        else:
            IP_DICT[ip][1] += 1
    
    IP_DICT[ip][2] = IP_DICT[ip][0] / (IP_DICT[ip][0] + IP_DICT[ip][1])

    if IP_DICT[ip][2] > 0.5 and IP_DICT[ip][0] - IP_DICT[ip][1] >= 3:
        block_prompt(ip)

def write_to_csv(feature):
    global count

    label = clf.predict([feature[1:2] + feature[3:12] + feature[14:29] + feature[30:33] + feature[34:37] + feature[38:47] + feature[48:51]])
    #feature.append(label[0])

    evaluate_ip(feature[0], label[0])
    evaluate_ip(feature[2], label[0])

    # for ip in IP_DICT:
    #     print(ip + " : " + str(IP_DICT[ip]))
    # print("=====================================")

def on_receive_packet(packet):
    if TCP not in packet and UDP not in packet:
        return

    status = check_status(packet)

    if status == 1:
        key = (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)

        if packet.time - flows[key].last_time >= 60:
            feature = flows[key].extract_feature()
            write_to_csv(feature)
            del flows[key]
            create_new_flow(packet, key)

        elif "R" in packet[TCP].flags or "F" in packet[TCP].flags:
            update_flow(packet, key, status)
            feature = flows[key].extract_feature()
            write_to_csv(feature)
            del flows[key]

        else:
            update_flow(packet, key, status)

    elif status == 2:
        key = (packet[IP].dst, packet[TCP].dport, packet[IP].src, packet[TCP].sport)

        if packet.time - flows[key].last_time >= 60:
            feature = flows[key].extract_feature()
            write_to_csv(feature)
            del flows[key]
            create_new_flow(packet, key)

        elif "R" in packet[TCP].flags or "F" in packet[TCP].flags:
            update_flow(packet, key, status)
            feature = flows[key].extract_feature()
            write_to_csv(feature)
            del flows[key]

        else:
            update_flow(packet, key, status)
            
    elif status == 3:
        key = (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
        create_new_flow(packet, key)
    elif status == 4:
        key = (packet[IP].src, packet[UDP].sport, packet[IP].dst, packet[UDP].dport)

        if packet.time - flows[key].last_time >= 60:
            feature = flows[key].extract_feature()
            write_to_csv(feature)
            del flows[key]
            create_new_flow(packet, key)

        else:
            update_flow(packet, key, status)
            
    elif status == 5:
        key = (packet[IP].dst, packet[UDP].dport, packet[IP].src, packet[UDP].sport)

        if packet.time - flows[key].last_time >= 60:
            feature = flows[key].extract_feature()
            write_to_csv(feature)
            del flows[key]
            create_new_flow(packet, key)
            
        else:
            update_flow(packet, key, status)
            
    else:
        key = (packet[IP].src, packet[UDP].sport, packet[IP].dst, packet[UDP].dport)
        create_new_flow(packet, key)

def main():
    with open(DATASET_FILE, "a+", newline="") as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(["ip_src", "port_src", "ip_dst", "port_dst", "ACK_flag_count", "ECE_flag_count", "PSH_flag_count", "RST_flag_count", "SYN_flag_count", "URG_flag_count", "FIN_flag_count", "CWR_flag_count", "fwd_window_size", "bwd_window_size", "protocol", "duration", "flow_bytes_p_sec", "flow_packets_p_sec", "fwd_packets_p_sec", "bwd_packets_p_sec", "tot_fwd_pkt", "tot_bwd_pkt", "max_len_fwd_pkt", "min_len_fwd_pkt", "avg_len_fwd_pkt", "std_len_fwd_pkt", "max_len_bwd_pkt", "min_len_bwd_pkt", "avg_len_bwd_pkt", "stdev_len_bwd_pkt", "max_flow_iat", "min_flow_iat", "avg_flow_iat", "stdev_flow_iat", "max_fwd_iat", "min_fwd_iat", "avg_fwd_iat", "stdev_fwd_iat", "max_bwd_iat", "min_bwd_iat", "avg_bwd_iat", "stdev_bwd_iat", "down_up_ratio", "avg_pkt_size", "max_fwd_header_len", "min_fwd_header_len", "avg_fwd_header_len", "stdev_fwd_header_len", "max_bwd_header_len", "min_bwd_header_len", "avg_bwd_header_len", "stdev_bwd_header_len", "label"])
        f.close()

    sniff(filter="ip and (tcp or udp)", prn=on_receive_packet, store=0)

if __name__ == "__main__":
    main()
