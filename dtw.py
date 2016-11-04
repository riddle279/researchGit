import numpy as np
from scipy.spatial.distance import euclidean
from fastdtw import fastdtw
import argparse
import sys
import timeit
import os
import re
import subprocess
import math
import statistics as st

def getopt():
    parser = argparse.ArgumentParser(description='convert pcap file to conversation')
    parser.add_argument("pcap", default=None, help='specify the pcap file you want to process')
    parser.add_argument("-f", "--folder", default=None, help='specify the folder you want to place the labeled flows')
    parser.add_argument("--keep", help="store all generated files", action="store_true")
    args = parser.parse_args()
    
    return args


def attribute(in_file):
    print("[*]Open input _conv file...")
    fp = open(in_file, 'r')
    fp2 = open("./conv_out/Waledac.br0.1.anonymous/Waledac.br0.1.anonymous_conv.txt", 'r')

    args = getopt()
    table = dict()
    payload_list1 = dict()
    payload_list2 = dict()
    fb_seq1 = dict()
    fb_seq2 = dict()
    interval1 = dict()
    interval2 = dict()
    distance_list = dict()
    table1 = dict()
    table2 = dict()
    mag_payload1 = dict()
    mag_payload2 = dict()
    valid_size_count = 0

    last_time = 0

    for line in fp:
        items = line.strip().split(' ')
        timetag = items[0]
        payload = int(items[4])
        srcip = items[1]
        dstip = items[2]
        timestamp = float(items[3])

        interval_time = timestamp - last_time

        payload_list1[timetag] = payload_list1.get(timetag,[[]])
        distance_list[timetag] = payload_list1.get(timetag,[[]])
        fb_seq1[timetag] = fb_seq1.get(timetag, [[]])
        interval1[timetag] = interval1.get(timetag, [[]])
        table1[timetag] = table1.get(timetag,[srcip,dstip])
        mag_payload1[timetag] = mag_payload1.get(timetag, [[]])


        payload_list1[timetag][0].append(payload)
        interval1[timetag][0].append(interval_time)

        if(srcip==table1[timetag][0]):
            fb_seq1[timetag][0].append(1)
        else:
            fb_seq1[timetag][0].append(0)

        last_time = timestamp

    last_time = 0

    for line in fp2:
        items = line.strip().split(' ')
        timetag = items[0]
        payload = int(items[4])
        srcip = items[1]
        dstip = items[2]
        timestamp = float(items[3])

        interval_time = timestamp - last_time

        payload_list2[timetag] = payload_list2.get(timetag,[[]])
        fb_seq2[timetag] = fb_seq2.get(timetag, [[]])
        interval2[timetag] = interval2.get(timetag, [[]])
        table2[timetag] = table2.get(timetag,[srcip,dstip])
        mag_payload2[timetag] = mag_payload2.get(timetag, [[]])

        payload_list2[timetag][0].append(payload)
        interval2[timetag][0].append(interval_time)

        if(srcip==table2[timetag][0]):
            fb_seq2[timetag][0].append(1)
        else:
            fb_seq2[timetag][0].append(0)

        last_time = timestamp

    for key in interval1:
        interval1[key][0].pop(0)

    for key in interval2:
        interval2[key][0].pop(0)
    
    
    #DFT
    print("[*]DFT")
    for key in payload_list1:
        if len(payload_list1[key][0]) > 10 and len(payload_list1[key][0]) < 40:
            dft_payload = np.fft.fft(payload_list1[key][0],norm = "ortho")
            mag_payload1[key][0] = abs(dft_payload)
            mag_payload1[key][0] = mag_payload1[key][0]/np.mean(mag_payload1[key][0]) #Normalize
            mag_payload1[key][0] = mag_payload1[key][0][1:math.floor((mag_payload1[key][0].size)/2+1)] #Only get the first half part
            
            #print(mag_payload1[key][0])
    
    
    for key in payload_list2:
        if len(payload_list2[key][0]) > 10 and len(payload_list2[key][0]) < 40:
            dft_payload = np.fft.fft(payload_list2[key][0],norm = "ortho")
            mag_payload2[key][0] = abs(dft_payload)
            mag_payload2[key][0] = mag_payload2[key][0]/np.mean(mag_payload2[key][0]) #Normalize
            mag_payload2[key][0] = mag_payload2[key][0][1:math.floor((mag_payload2[key][0].size)/2+1)] #Only get the first half part
            
            #print(mag_payload2[key][0])
    
    
    #payload_mag distance(Normalized)
    for key in mag_payload2:
        if len(mag_payload2[key][0]) > 5 and len(mag_payload2[key][0]) < 20:
            valid_size_count += 1
    print("Number of Conversation in Valid Size:", end = '')
    print(valid_size_count)
    
    print("Average distance of the sequence:")
    for conv_1 in mag_payload1:
        if len(mag_payload1[conv_1][0]) > 5 and len(mag_payload1[conv_1][0]) < 20:
            distance = 0
            for conv_2 in mag_payload2:
                if len(mag_payload2[conv_2][0]) > 5 and len(mag_payload2[conv_2][0]) < 20:
                    distance += fastdtw(mag_payload1[conv_1][0], mag_payload2[conv_2][0], dist=euclidean)[0]
            distance /= valid_size_count

            distance_list[conv_1][0].append(distance)
            print(distance)

    

    '''
    #payload distance
    for key in payload_list2:
        if len(payload_list2[key][0]) > 5 and len(payload_list2[key][0]) < 20:
            valid_size_count += 1
    print("Number of Conversation in Valid Size:", end = '')
    print(valid_size_count)
   
    
    print("Average distance of the sequence:")
    for conv_1 in payload_list1:
        if len(payload_list1[conv_1][0]) > 5 and len(payload_list1[conv_1][0]) < 20:
            distance = 0
            for conv_2 in payload_list2:
                if len(payload_list2[conv_2][0]) > 5 and len(payload_list2[conv_2][0]) < 20:
                    distance += fastdtw(payload_list1[conv_1][0], payload_list2[conv_2][0], dist=euclidean)[0]
            distance /= valid_size_count

            distance_list[conv_1][0].append(distance)
            print(distance)
    '''

    '''
    #fb_seq distance
    for key in fb_seq2:
        if len(fb_seq2[key][0]) > 5 and len(fb_seq2[key][0]) < 20:
            valid_size_count += 1
           
    print("Number of Conversation in Valid Size:", end = '')
    print(valid_size_count)


    print("Average distance of the sequence:")
    for conv_1 in fb_seq1:
        if len(fb_seq1[conv_1][0]) > 5 and len(fb_seq1[conv_1][0]) < 20:
            distance = 0
            for conv_2 in fb_seq2:
                if len(fb_seq2[conv_2][0]) > 5 and len(fb_seq2[conv_2][0]) < 20:
                    distance += fastdtw(fb_seq1[conv_1][0], fb_seq2[conv_2][0], dist=euclidean)[0]
            distance /= valid_size_count

            distance_list[conv_1][0].append(distance)
            print(distance)
    '''

    '''
    #interval distance
    for key in interval2:
        if len(interval2[key][0]) > 5 and len(interval2[key][0]) < 20:
            valid_size_count += 1

    print("Number of Conversation in Valid Size:", end = '')
    print(valid_size_count)
    
    
    print("Average distance of the sequence:")
    for conv_1 in interval1:
        if len(interval1[conv_1][0]) > 5 and len(interval1[conv_1][0]) < 20:
            #print("conv_1 = ", end = '')
            #print(interval1[conv_1][0])
            distance = 0
            for conv_2 in interval2:
                if len(interval2[conv_2][0]) > 5 and len(interval2[conv_2][0]) < 20:
                    #print("conv_2 = ",end = '')
                    #print(interval2[conv_2][0])
                    distance += fastdtw(interval1[conv_1][0], interval2[conv_2][0], dist=euclidean)[0]
            distance /= valid_size_count
    
            distance_list[conv_1][0].append(distance)
            print(distance)
    '''

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

    attribute(conv_name)
    x = np.array([0.00899505615234375, 0.08645892143249512, 0.022488117218017578, 0.0874779224395752,8.20159912109375e-05, 0.12540197372436523])

    y = np.array([[0.004998922348022461, 0.301501989364624, 0.022001028060913086, 0.08765196800231934, 6.103515625e-05, 0.268341064453125]])

    dis = fastdtw(x, y, dist=euclidean)[0]
    print(dis)

if __name__ == "__main__":
    main()
