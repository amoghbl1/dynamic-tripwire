#!/usr/bin/env python3
import argparse
import json
import sys
import matplotlib.pyplot as plt
from collections import defaultdict

def main():
    parser = argparse.ArgumentParser(description='HTML difference generator.')
    parser.add_argument('--results', help='Results file to write stats to.', type=str, nargs='?', default='successfulPageLoads.json')
    parser.add_argument('--cdffile', help='File to write the CDF figure to.', type=str, nargs='?', default='passing_cdf.jpg')
    args = parser.parse_args(sys.argv[1:])
    results_file = args.results
    cdf_file = args.cdffile
    cdf_data = defaultdict(int)
    # We need pageload file to be specified.
    # print("Processing:", results_file)
    # First try loading results file.
    try:
        with open(results_file, "r") as inf:
            saved_results = json.load(inf)
    except FileNotFoundError:
        print("Results file not found :/")
        return
    except json.decoder.JSONDecodeError:
        print("Error decoding results file :/")
        return
    # Load in domains we want to count.
    c0 = 0
    c1 = 0
    for k, v in saved_results.items():
        overlap_domains = v["overlap_domains"]
        if len(overlap_domains) == 0:
            c0 += 1
            print(k)
        elif len(overlap_domains) == 1:
            c1 += 1
    print("Done writing CDF:", cdf_file, "0:", c0, "1:", c1)

if __name__ == "__main__":
    main()
