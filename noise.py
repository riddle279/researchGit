import argparse
import sys 
import timeit
import os
import re
import subprocess
import math
import statistics as st
import numpy as np
import random


def getopt():
    parser = argparse.ArgumentParser(description='convert pcap file to conversation')
    parser.add_argument("pcap", default=None, help='specify the pcap file you want to process')
    parser.add_argument("-f", "--folder", default=None, help='specify the folder you want to place the labeled flows')
    parser.add_argument("--keep", help="store all generated files", action="store_true")

    args = parser.parse_args()
    return args


#add udp.length (header+payload)
def pcap2txt(pcap_file, txt_file):
    cmd = "tshark -r  %s -e frame.time_epoch -e ip.proto -e ip.src -e ip.dst -e eth.src \
    -e eth.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e frame.len \
    -e tcp.flags -e tcp.seq -e tcp.ack -e tcp.len -e udp.length -e tcp.stream -e udp.stream \
    -Tfields -E separator=, > %s" %(pcap_file, txt_file)
    

    cmd2 = "tshark -r %s -e frame.time_epoch -e ip.proto -e ip.src -e ip.dst -e eth.src \
            -e eth.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e frame.len \
            -e tcp.flags -e tcp.seq -e tcp.ack -e tcp.len -e udp.length -e tcp.stream -e udp.stream -Y \"dns && not icmp\" \
            -Tfields -E separator=, > %s" %(pcap_file, txt_file)


    print(cmd)
    subprocess.call(cmd, shell=True)

    #print(cmd2)
    #subprocess.call(cmd2, shell=True)


#[8]udp_srcport, [9]udp_dstport, [10]frame length [14]tcp_payload_len [15]udp_payload_len
def pkt2list(txt_file, out_file):
    attr = ['Time', 'protocol', 'src_ip', 'dst_ip', 'src_mac', 'dst_mac', 'tcp_srcport',\
    'tcp_dstport', 'udp_srcport', 'udp_dstport', 'pkt_len', 'tcp_flag',\
    'tcp_seq', 'tcp_ack', 'tcp_len', 'udp_len', 'tcp_stream', 'udp_stream', 'stream_label']

    pkt_list = list()
    fp = open(txt_file, 'r')
    fw = open(out_file, 'w')
    for line in fp:
        pkt = line.strip().split(',')
        try:
            proto = int(pkt[1])
        except:                  
            print(pkt)
            continue
        if proto == 17 and len(pkt) == 18:
            if pkt[8] and pkt[9] and pkt[17]: # udp src port and dst port
                pkt[15] = str(int(pkt[15])-8)
                pkt.append("stream_udp_%s"% pkt[17])
                pkt_list.append(pkt)
                string = ",".join(pkt) + '\n'
                fw.write(string)
        elif proto == 6 and len(pkt) == 18:
            if pkt[6] and pkt[7] and pkt[16]: # tcp src port and dst port
                pkt.append("stream_tcp_%s" % pkt[16])
                pkt_list.append(pkt)
                string = ",".join(pkt) + '\n'
                fw.write(string)
        else:
            continue
    fp.close()
    fw.close()
    return pkt_list, attr


def label2conv(pkt_list_in,gap):
    #fw = open(out_file, 'w')
    pkt_list = list()
    for pkt in pkt_list_in:
        if pkt[8] and pkt[9] and pkt[17]: #udp
            if pkt[15] != '0': #payload size > 0
                pkt_list.append([pkt[2],pkt[3],pkt[0],pkt[15],pkt[9]])
        elif pkt[6] and pkt[7] and pkt[16]: #tcp
            if pkt[14] != '0': #payload size > 0
                pkt_list.append([pkt[2],pkt[3],pkt[0],pkt[14],pkt[7]])

    pkt_dict = dict()
    convID = 0
    cur_time = 0
    #conv_dict = dict()
    conv_list = list()

    for item in pkt_list:
        tag = tuple(sorted([item[0], item[1]]))
        #pkt_dict[tag] = pkt_dict.get(tag, [[],[],0])
        pkt_dict[tag] = pkt_dict.get(tag, [[],[],[],[],[],0])
        pkt_dict[tag][0].append(item[0]) #src
        pkt_dict[tag][1].append(item[1]) #dst
        pkt_dict[tag][2].append(item[2]) #time
        pkt_dict[tag][3].append(item[3]) #payload
        pkt_dict[tag][4].append(item[4]) #dstport
    
    for keys in pkt_dict.keys():
        convID = convID+1
        
        for tuples in zip(pkt_dict[keys][0],pkt_dict[keys][1],pkt_dict[keys][2],pkt_dict[keys][3],pkt_dict[keys][4]):
            if float(tuples[2]) - cur_time > gap:
                convID = convID+1
            
            conv_list.append([convID,tuples[0],tuples[1],tuples[2],tuples[3],tuples[4]])
            cur_time = float(tuples[2])

    #fw.write(conv_list)
    return conv_list

def attribute(in_file):
    print("[*]Open input _conv file...")
    fp = open(in_file, 'r')

    args = getopt()
    pname = args.pcap.rsplit('.pcap')[0].split('/')[-1]
    out_file = pname + '_attr.txt'
                                            
    fw = open(out_file, 'w')  
    #fw2 = open('./fb_seq_eMule.txt','w')

    table = dict()
    payload_list = dict()
    interval = dict()
    fb_seq = dict()
    Dport_seq = dict()
    small_bi_seq = dict()
    quan_seq = dict()
    time = dict()

    print("[*]Parameter initialization")
    get_on = 0
    last_time = 0
    dft_cal = 1

    print("[*]Append Interval time")
    for line in fp:
        var = random.randint(0, 1)
        noise = random.randint(25,50) / 100
        
        items = line.strip().split(' ')
        timetag = items[0]
        timestamp = float(items[3])

        interval_time = timestamp - last_time
        #Noise of interval
        #interval_time += interval_time * var * noise
        interval[timetag] = interval.get(timetag, [[]])
        interval[timetag][0].append(interval_time)

        last_time = timestamp

    print("[*]Initial the feature table")
    fp.seek(0)
    for line in fp:
        items = line.strip().split(' ')
        timetag = items[0]
        srcip = items[1]
        dstip = items[2]
        timestamp = float(items[3])
        payload = int(items[4])
        Dport = int(items[5])

        table[timetag] = table.get(timetag,[srcip,dstip,timestamp,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,payload,0])
        
    for key in interval:      
        interval[key][0].pop(0)                                    
        table[key][3] = sum(interval[key][0])
        table[key][63] = np.mean(interval[key][0])

    print("[*]Finish initialization")

    xxx = 0
    fp.seek(0)
    for line in fp:
        var = random.randint(0, 1)
        noise = random.randint(25,50) / 100

        items = line.strip().split(' ')
        timetag = items[0]
        srcip = items[1]
        dstip = items[2]
        timestamp = float(items[3])
        payload = int(items[4])
        Dport = int(items[5])
        small_lb = 0  #lower bound of small packets
        small_ub = 300 #upper bound of small packets

        #print(xxx)
        xxx += 1

        #Noise of payload
        #payload += payload * var * noise

        #print("start append")
        fb_seq[timetag] = fb_seq.get(timetag, [[]])
        Dport_seq[timetag] = Dport_seq.get(timetag, [[]])
        small_bi_seq[timetag] = small_bi_seq.get(timetag, [[]])
        quan_seq[timetag] = quan_seq.get(timetag, [[]])

        last_time = timestamp
        Dport_seq[timetag][0].append(Dport)
    
        #[0]srcip [1]dstip [2]start time [3]Duration [4]payload_sent [5]payload_rcv [6]TBT(payload) [7]APL [8]PV
        #[9]BS [10]Bytes sent per sec [11]Bytes rcv per sec [12]PX
        #[13]pkt sent [14]pkt received [15]pkt sent per sec [16]pkt rcv per sec[17]PPS
        #[18]payload_mag_var[19]min_interval [20]max_interval [21]interval_mag_var
        #[22]payload_mag_max [23]interval_mag_max [24]payload_energy [25]interval_energy
        #[26]fb_mag_var[27]fb_mag_max[28]fb_energy[29]Dport_mag_var[30]Dport_mag_max[31]Dport_energy
        #[32]payload_peak1 [33]payload_peak2 [34]payload_peak3 [35]payload_peak4 [36]payload_peak5
        #[37]interval_peak1 [38]interval_peak2 [39]interval_peak3 [40]interval_peak4 [41]interval_peak5
        #[42]payload_dft_a [43]payload_dft_b [44]IOPR [45]num_of_small [46]propotion_of_small
        #[47]small_bi_var #[48]small_bi_max [49]small_bi_energy [50]PMP [51]PLP [52]PHP 
        #[53]medium [54]large [55]huge [56]quan_var [57]quan_max [58]quan_energy [59]payload_reg [60]interval_reg
        #[61]DPL [62]FPS [63]AIT


        payload_list[timetag] = payload_list.get(timetag,[[]])
        time[timetag] = time.get(timetag, [[]])


        table[timetag][6] += payload #[6]payload exchange
        table[timetag][12] += 1 #[12]Total pkt number
        table[timetag][7] = table[timetag][6] / table[timetag][12] #[7]APL
        payload_list[timetag][0].append(payload)
        time[timetag][0].append(timestamp-table[timetag][2])

        if payload >= small_lb and payload <= small_ub: #small
            table[timetag][45] += 1  #[45]
            table[timetag][46] = table[timetag][45] / table[timetag][12] #[46]
            small_bi_seq[timetag][0].append(50)
            quan_seq[timetag][0].append(1)

        else:
            small_bi_seq[timetag][0].append(1500)
            if payload > 300 and payload <= 1000: #medium
                table[timetag][53] += 1
                table[timetag][50] = table[timetag][53] / table[timetag][12] #[50]PMP
                quan_seq[timetag][0].append(2)

            elif payload > 1000 and payload <= 2000: #large
                table[timetag][54] += 1
                table[timetag][51] = table[timetag][54] / table[timetag][12] #[51]PLP
                quan_seq[timetag][0].append(3)

            else:                                 #huge
                table[timetag][55] += 1
                table[timetag][52] = table[timetag][55] / table[timetag][12]  #[52]PHP
                quan_seq[timetag][0].append(4)
        
        if(table[timetag][3] != 0): 
            table[timetag][9] = table[timetag][6] / table[timetag][3] #[9]BS
            table[timetag][10] = table[timetag][4] / table[timetag][3] #[10]Bytes sent per sec
            table[timetag][11] = table[timetag][5] / table[timetag][3] #[11]Bytes received per sec
            

        if(srcip==table[timetag][0]):
            fb_seq[timetag][0].append(1)
            table[timetag][4] += payload #[4]payload_sent
            table[timetag][13] += 1      #[13]pkt sent

        else:
            fb_seq[timetag][0].append(0)
            table[timetag][5] += payload #[5]payload_rcv
            table[timetag][14] += 1      #[14]pkt rcved

        if(table[timetag][3] != 0):
            table[timetag][15] = table[timetag][13] / table[timetag][3] #[15]pkt sent per sec
            table[timetag][16] = table[timetag][14] / table[timetag][3] #[16]pkt rcved per sec
            table[timetag][17] = table[timetag][12] / table[timetag][3] #[17]pkt per sec

        table[timetag][44] = table[timetag][14] / table[timetag][13] #[44]IOPR
        

    print("End 3")

    fp.seek(0)

    for line in fp: #[8]Var of payload
        items = line.strip().split(' ')
        payload = int(items[4])
        timetag = items[0]
        table[timetag][8] += (payload-table[timetag][7]) * (payload-table[timetag][7])

    
    #table[timetag][8] /= table[timetag][12]


    for key in table:
        table[key][8] /= table[key][12]
        if(len(interval[key][0]) > 0):
            table[key][19] = min(interval[key][0])  #[19]min_interval
            table[key][20] = max(interval[key][0])  #[20]max_interval
        else:   
            table[key][19] = 0
            table[key][20] = 0

    ddd = 1
    maxx=0

    
    print("[*]Start DFT")
    if dft_cal == 1:
        for timetag in table.keys():
            if len(payload_list[timetag][0]) < 120000 and len(payload_list[timetag][0])>10:
                table[timetag][61] = len(list(set(payload_list[timetag][0]))) / table[timetag][12]
                dft_payload = np.fft.fft(payload_list[timetag][0],norm = "ortho")
                mag_payload = abs(dft_payload)
                mag_payload = mag_payload/np.mean(mag_payload) #Normalize
                mag_payload = mag_payload[1:math.floor((mag_payload.size)/2+1)] #Only get the first half part

                max_index = sorted(range(len(mag_payload)), key=lambda i: mag_payload[i])[-1] + 1

                reg = mag_payload/np.mean(mag_payload)
                reg = reg/len(payload_list[timetag][0])
                table[timetag][59] = max(reg) - min(reg)

                mag_payload = sorted(mag_payload,reverse=True) #sorted in descending order
                if len(mag_payload) > 10:                        #only get the top 10 if len(mag_payload > 10)
                    mag_payload = mag_payload[:10]

                if len(mag_payload) < 10:
                    table[timetag][18] = 777
                    table[timetag][22] = 777
                    table[timetag][24] = 777
                    table[timetag][42] = 777
                    table[timetag][43] = 777


                else:
                    table[timetag][18] = st.pvariance(mag_payload) #[18]VAR of mag_payload
                    table[timetag][22] = max(mag_payload)          #[22]max of mag_payload
                    square = [i**2 for i in mag_payload]
                    table[timetag][24] = sum(square)               #[24]Energy of payload
                    table[timetag][42] = dft_payload[max_index].real #[42] payload_dft_a
                    table[timetag][43] = dft_payload[max_index].imag #[43] payload_dft_b


                if len(mag_payload)>=5:
                    table[timetag][32] = mag_payload[0]
                    table[timetag][33] = mag_payload[1]
                    table[timetag][34] = mag_payload[2]
                    table[timetag][35] = mag_payload[3]
                    table[timetag][36] = mag_payload[4]
       
                else:
                    table[timetag][32] = 0
                    table[timetag][33] = 0
                    table[timetag][34] = 0
                    table[timetag][35] = 0
                    table[timetag][36] = 0

    ####################################################################################################
            if len(small_bi_seq[timetag][0]) < 120000 and len(small_bi_seq[timetag][0])>10:
                dft_small_bi = np.fft.fft(small_bi_seq[timetag][0],norm = "ortho")
                mag_small_bi = abs(dft_small_bi)                           
                mag_small_bi = mag_small_bi[1:math.floor((mag_small_bi.size)/2+1)] #Only get the first half part

                mag_small_bi = sorted(mag_small_bi, reverse=True) #sorted in descending order
                if len(mag_small_bi) > 10:  #only get the top 10 if len(mag_small_bi > 10)
                    mag_small_bi = mag_small_bi[:10]

                if len(mag_small_bi) < 10:
                    table[timetag][47] = 0
                    table[timetag][48] = 0
                    table[timetag][49] = 0

                else:
                    table[timetag][47] = st.pvariance(mag_small_bi) #[47]VAR of mag_small_bi
                    table[timetag][48] = max(mag_small_bi)          #[48]max of mag_small_bi
                    square = [i**2 for i in mag_small_bi]
                    table[timetag][49] = sum(square)               #[49]Energy of small_bi


            if len(quan_seq[timetag][0]) < 120000 and len(quan_seq[timetag][0])>10:
                dft_quan = np.fft.fft(quan_seq[timetag][0], norm = "ortho")
                mag_quan = abs(dft_quan)
                mag_quan = mag_quan[1:math.floor((mag_quan.size)/2+1)] #Only get the first half part

                mag_quan = sorted(mag_quan, reverse=True) #sorted in descending order
                if len(mag_quan) > 10:  #only get the top 10 if len(mag_quan > 10)
                    mag_quan = mag_quan[:10]

                if len(mag_quan) < 10:
                    table[timetag][56] = 0
                    table[timetag][57] = 0
                    table[timetag][58] = 0

                else:
                    table[timetag][56] = st.pvariance(mag_quan) #[56]VAR of mag_quan
                    table[timetag][57] = max(mag_quan)         #[57]max of mag_quan
                    square = [i**2 for i in mag_quan]
                    table[timetag][58] = sum(square)           #[58]Energy of quan
            
            
            if len(interval[timetag][0]) < 120000 and len(interval[timetag][0])>10:
                dft_interval = np.fft.fft(interval[timetag][0],norm = "ortho")
                mag_interval = abs(dft_interval)
                mag_interval = mag_interval/np.mean(mag_interval)   #Normalize
                mag_interval = mag_interval[1:math.floor((mag_interval.size)/2+1)] #Only get the first half part

                reg = mag_interval/np.mean(mag_interval)
                reg = reg/len(interval[timetag][0])
                table[timetag][60] = max(reg) - min(reg)


                mag_interval = sorted(mag_interval, reverse=True)    #sorted in descending order
                if len(mag_interval) > 10:                           #only get the top 10 if len(mag_payload > 10) 
                    mag_interval = mag_interval[:10]

                if len(mag_interval) < 10:
                    table[timetag][21] = 0
                    table[timetag][23] = 0
                    table[timetag][25] = 0

                else:
                    table[timetag][21] = st.pvariance(mag_interval)  #[21]VAR of mag_interval
                    table[timetag][23] = max(mag_interval)           #[23]max of mag_interval
                    square = [i**2 for i in mag_interval]
                    table[timetag][25] = sum(square)                 #[25]Energy of interval

                
                if len(mag_interval)>=5:
                    table[timetag][37] = mag_interval[0]
                    table[timetag][38] = mag_interval[1]
                    table[timetag][39] = mag_interval[2]
                    table[timetag][40] = mag_interval[3]
                    table[timetag][41] = mag_interval[4]
       
                else:
                    table[timetag][37] = 0
                    table[timetag][38] = 0
                    table[timetag][39] = 0
                    table[timetag][40] = 0
                    table[timetag][41] = 0
                
                
########################################################################################################      
            if len(fb_seq[timetag][0]) < 120000 and len(fb_seq[timetag][0]) > 10:
                dft_fb = np.fft.fft(fb_seq[timetag][0],norm = "ortho")
                mag_fb = abs(dft_fb)
                mag_fb = mag_fb/np.mean(mag_fb)   #Normalize
                mag_fb = mag_fb[1:math.floor((mag_fb.size)/2+1)] #Only get the first half part
                mag_fb = sorted(mag_fb, reverse=True)    #sorted in descending order

                if len(mag_fb)>10:                             #only get the top 10 if len(mag_payload > 10) 
                    mag_fb = mag_fb[:10]

                if len(mag_fb) < 10:
                    table[timetag][26] = 0
                    table[timetag][27] = 0
                    table[timetag][28] = 0

                else:
                    table[timetag][26] = st.pvariance(mag_fb)   #[26]fb_mag_var
                    table[timetag][27] = max(mag_fb)            #[27]fb_mag_max
                    square = [i**2 for i in mag_fb]
                    table[timetag][28] = sum(square)            #[28]fb_energy

            ###########################################################################################
            # Dport_seq DFT
            if len(Dport_seq[timetag][0]) < 120000 and len(Dport_seq[timetag][0]) > 10:
                dft_Dport = np.fft.fft(Dport_seq[timetag][0],norm = "ortho")                                     
                mag_Dport = abs(dft_Dport)                                                                       
                mag_Dport = mag_Dport/np.mean(mag_Dport)   #Normalize                                               
                mag_Dport = mag_Dport[1:math.floor((mag_Dport.size)/2+1)] #Only get the first half part             
                mag_Dport = sorted(mag_Dport, reverse=True)    #sorted in descending order

                if len(mag_Dport)>10:                             #only get the top 10 if len(mag_payload > 10) 
                    mag_Dport = mag_Dport[:10]
                             
                if len(mag_Dport) < 10:
                    table[timetag][29] = 0
                    table[timetag][30] = 0
                    table[timetag][31] = 0
                              
                else:   
                    table[timetag][29] = st.pvariance(mag_Dport)   #[29]Dport_mag_var
                    table[timetag][30] = max(mag_Dport)            #[30]Dport_mag_max
                    square = [i**2 for i in mag_Dport]
                    table[timetag][31] = sum(square)               #[31]Dport_energy
            #if table[timetag][29] == 0 and table[timetag][24] > 0:
                #print(Dport_seq[timetag][0])
        
        #print(ddd)
        #ddd = ddd+1

        

    feature_sel = [18,22,24,32,33,34,35,36,42,43,47,48,49,56,57,58,19,20,21,23,25,37,38,39,40,41,26,27,28,59,60,12,62,7,6,61,9,17,3,8,63,44]
    #feature_sel = [8]
    feature_name = ['srcip', 'dstip', 'start time', 'duration', 'payload_sent', 'payload_rcv', 'TBT', 'APL', 
                    'PV', 'BS', 'Bytes sent per sec', 'Bytes rcv per sec', 'PX', 'pkt sent',
                    'pkt rcved', 'pkt sent per sec', 'pkt rcv per sec', 'PPS', 'payload_mag_var',
                    'min_interval', 'max_interval', 'mag_interval_var', 'payload_mag_max', 'interval_mag_max',
                    'payload_energy', 'interval_energy', 'fb_mag_var', 'fb_mag_max', 'fb_energy', 'Dport_mag_var',
                    'Dport_mag_max', 'Dport_energy', 'payload_peak1', 'payload_peak2', 'payload_peak3',
                    'payload_peak4', 'payload_peak5', 'interval_peak1', 'interval_peak2', 'interval_peak3',
                    'interval_peak4', 'interval_peak5', 'payload_dft_a', 'payload_dft_b', 'IOPR', 'small',
                    'PSP', 'small_bi_var', 'small_bi_max', 'small_bi_energy', 'PMP', 'PLP', 'PHP', 
                    'medium', 'large', 'huge', 'quan_var', 'quan_max', 'quan_energy','payload_reg', 'interval_reg',
                    'DPL', 'FPS', 'AIT']


    #print("Feature you select:", end = " ")
    print(feature_sel)

    timeline = list()

    '''
    for key in time:
        if table[key][12]>20 and table[key][3] > 40 and table[key][3] < 50:
            timeline.append(time[key])

    for element in timeline:
        print(element)
        print("-----------------------------------------------")
    '''

    
    for i in feature_sel:
        if i == feature_sel[-1]:
            fw.write("%s,label" % feature_name[i])
        else:
            fw.write("%s," % feature_name[i])
    fw.write("\n")
       

    for key in sorted(table, key=lambda k:table[k][2]):
        if(table[key][12]>20): #Using only when ...
            for i in feature_sel:
                #fw.write("%s " % table[key][i])
                if i == feature_sel[-1]:
                    fw.write("%.6f,botnet" % table[key][i])
                    #fw.write("%s" % payload_list[key])
                else:
                    fw.write("%.6f," % table[key][i])
            fw.write("\n")                                                                   
    #print(num_features)
    fp.close()
    fw.close()


def main():
    args = getopt()
    pname = args.pcap.rsplit('.pcap')[0].split('/')[-1]

    if args.folder:
        folder = args.folder.strip('/') + '/' + pname + '/'
    else:
        folder = './'

    if not os.path.exists(folder):
        os.makedirs(folder)

    conv_name = folder + pname + '_conv.txt'

    '''    
    #Produce _pkts.txt file
    time1 = timeit.default_timer()
    txt_name = folder + pname + '_pkts.txt'
    pcap2txt(args.pcap, txt_name)

    #Produce _labeled.txt file
    time2 = timeit.default_timer()
    labeled_file_name = folder + pname + '_labeled.txt'
    pkt_list, attr = pkt2list(txt_name, labeled_file_name)

    #Produce _conv.txt file
    conv_name = folder + pname + '_conv.txt'
    conv_list = label2conv(pkt_list,2000)
    
    
    fw = open(conv_name, 'w')
    for conv in conv_list:
        for item in conv:
            fw.write(str(item))
            fw.write(" ")
        fw.write('\n')
    fw.close()
    '''

    attribute(conv_name)

if __name__ == "__main__":
    main()
