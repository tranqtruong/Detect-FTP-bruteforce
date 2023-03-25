#!/usr/bin/env python3
# capture.py
import time
import pyshark
import keyboard # run with sudo in linux, sudo python3 -m pip install keyboard
import multiprocessing
import threading
import csv

# global var
iface_name = 'VMware Network Adapter VMnet8'
filter_string = ''
pcap_out_file_name = 'monitor.pcap'
csv_out_file_name = 'out2.csv'

ftp_countdown = True
ftp_ip_risk = {} #{"ip_pair":{"resquet_pass":0, "respone_530":0, "attack_start":'1h:30m:4s'}}
log = []


def count_down(time_s, key_string):
    global ftp_countdown

    if key_string == 'program':
        time.sleep(time_s)
        return True
        
    elif key_string == 'ftp':
        while True:
            if ftp_countdown == True:
                time.sleep(time_s)
                ftp_countdown = False

def get_ip_pair(packet):
    source_ip, dest_ip = '', ''

    if 'ip' in packet and 'src' in packet.ip.field_names:
        source_ip = str(packet.ip.src)
    elif 'ipv6' in packet and 'src' in packet.ipv6.field_names:
        source_ip = str(packet.ipv6.src)
    elif 'eth' in  packet:
        if 'src_oui_resolved' in packet.eth.field_names:
            source_ip += str(packet.eth.src_oui_resolved)
        if 'src' in packet.eth.field_names:
            source_ip = '{} ({})'.format(source_ip, str(packet.eth.src))

    if 'ip' in packet and 'dst' in packet.ip.field_names:
        dest_ip = str(packet.ip.dst)
    elif 'ipv6' in packet and 'dst' in packet.ipv6.field_names:
        dest_ip = str(packet.ipv6.dst)
    elif 'eth' in  packet:
        if 'dst_oui_resolved' in packet.eth.field_names:
            dest_ip += str(packet.eth.dst_oui_resolved)
        if 'dst' in packet.eth.field_names:
            dest_ip = '{} ({})'.format(dest_ip, str(packet.eth.dst))
    return source_ip, dest_ip

def matched_signature_FTP_BF(packet):
    global ftp_ip_risk
    if 'ftp' in packet:
        if 'request_command' in packet.ftp.field_names and str(packet.ftp.request_command).strip().upper() == 'PASS':
            ip_src, ip_dst = get_ip_pair(packet)
            key = "{} -> {}".format(ip_src, ip_dst)
            date_time_packet = ''
            if 'sniff_time' in dir(packet):
                date_time_packet = str(packet.sniff_time)
            
            if key not in ftp_ip_risk:
                ftp_ip_risk[key] = {"resquet_pass":1, "respone_530":0, "attack_start":date_time_packet}
            else:
                ftp_ip_risk[key]["resquet_pass"] += 1
        
        elif 'response_code' in packet.ftp.field_names and int(packet.ftp.response_code) == 530:
            ip_src, ip_dst = get_ip_pair(packet)
            key = "{} -> {}".format(ip_dst, ip_src)
            date_time_packet = ''
            if 'sniff_time' in dir(packet):
                date_time_packet = str(packet.sniff_time)
            
            if key not in ftp_ip_risk:
                ftp_ip_risk[key] = {"resquet_pass":0, "respone_530":1, "attack_start":date_time_packet}
            else:
                ftp_ip_risk[key]["respone_530"] += 1
            pass
        pass

    pass

def detect_FTP_BruteForce(save_log):
    global ftp_countdown, ftp_ip_risk
    time.sleep(0.5)
    thread1 = threading.Thread(target=count_down, args=(60, 'ftp'))
    thread1.start()
    
    while True:
        for ip_pair in ftp_ip_risk:
            if ftp_ip_risk[ip_pair]["resquet_pass"] >= 10 or ftp_ip_risk[ip_pair]["respone_530"] >= 10:
                message = "Warning! {}: FTP Potential Brute Force Attack: start at {}".format(ip_pair, ftp_ip_risk[ip_pair]["attack_start"])
                print(message)
                time.sleep(0.5)
                pass

        if ftp_countdown == False:
            ftp_ip_risk.clear()
            ftp_countdown = True
            #time.sleep(1)
        #time.sleep(0.5)
    pass

def monitor():
    print('*start monitoring')
    global ftp_ip_risk
    
    thread2 = threading.Thread(target=detect_FTP_BruteForce, args=(False, ))
    thread2.start()
    packets = pyshark.LiveCapture(interface=iface_name, output_file=pcap_out_file_name)
    for packet in packets.sniff_continuously():
        matched_signature_FTP_BF(packet)
        pass

def stop_program(time_h):
    print('Press "q" to stop monitor and quit.')
    process3 = multiprocessing.Process(target=count_down, args=(int(time_h)*60*60, 'program',))
    process3.start()
    while True:
        if keyboard.is_pressed('q'):
            process3.kill()
            return True
        if not process3.is_alive():
            return True



if __name__ == '__main__':
    p1 = multiprocessing.Process(target=stop_program, args=(1,))
    p2 = multiprocessing.Process(target=monitor)
    
    p1.start()
    p2.start()

    p1.join()
    
    if not p1.is_alive():
        p2.terminate()
        print('bye.')