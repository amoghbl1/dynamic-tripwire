#!/usr/bin/env python3
import pyshark
import os
import pickle
import random
import sys
from multiprocessing import Process
from os import path
import json

def main():
    # Process all .pcaps for every browser, in a parallelized way
    # Can control the amount of parallelization
    if len(sys.argv) < 2:
        print("Please provide at least 1 path to process .pcap files from.")
        return
    else:
        pcap_paths = sys.argv[1:]
    pcap_files = set()
    for path in pcap_paths:
        pcap_files.update(get_files_from_path(path + '/logs/', ".pcap"))
    processes = []
    for pcap in pcap_files:
        package_hash = pcap.split("/")[-1]
        package_hash = "-".join(package_hash.split("-")[:2])
        p = Process(target=process_browser_pcaps, args=(pcap, package_hash))
        processes.append(p)
        p.start()
        while len(processes) >= 16:
            for p in processes:
                p.join(0.1)
                if not p.is_alive():
                    processes.remove(p)
    for p in processes:
        p.join()

def get_files_from_path(path, extension):
    retset = set()
    for f in os.listdir(path):
        if f.endswith(extension):
            retset.add(path + "/" + f) # Need to track path as well
    return retset

# Process all .pcaps for a particular device for TLS analysis
def process_browser_pcaps(pcap, browser_name):
    out_dir = "/".join(pcap.split("/")[:-1])
    print("Processing", pcap)
    weak_ciphers = set()
    problem_ciphers = set()
    processed = 0
    try:
        shark_cap = pyshark.FileCapture(pcap,
                                        display_filter = "not tcp.analysis.retransmission and not "
                                                         "tcp.analysis.fast_retransmission and "
                                                         "ssl.handshake.type == 1")
    except:
        print("Exception parsing pcap file")
        pass
    while True:
        try:
            packet = shark_cap.next()
            processed += 1
            # print(packet)
            tls_printed = str(packet.tls)
            weak_ciphers = weak_ciphers.union(check_weak_cipher(tls_printed))
            problem_ciphers = problem_ciphers.union(check_problematic_cipher(tls_printed))
        except:
            break
    try:
        shark_cap.close()
    except:
        pass
    # Write results to out_dir
    to_write = {"packets": processed}
    if len(weak_ciphers) > 0:
        to_write["weak_ciphers"] = list(weak_ciphers)
    if len(problem_ciphers) > 0:
        to_write["problem_ciphers"] = list(problem_ciphers)
    with open(out_dir + "/" + browser_name + ".cipher", "w") as ouf:
        json.dump(to_write, fp=ouf)

def check_weak_cipher(printed):
    weaks = set()
    for line in printed.splitlines():
        if "Cipher Suite: " in line:
            if "_RC4" in line or "_DES" in line or "_3DES" in line or "_DES" in line:
                weaks.add((line.split(":")[1]).split(" ")[1])
    return weaks

def check_problematic_cipher(printed):
    problems = set()
    for line in printed.splitlines():
        if "Cipher Suite:" in line:
            if "_EXPORT" in line or "_NULL" in line or "_anon" in line:
                problems.add((line.split(":")[1]).split(" ")[1])
    return problems

if __name__ == "__main__":
    main()
