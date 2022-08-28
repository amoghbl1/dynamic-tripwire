#!/usr/bin/env python3
import argparse
import json
import sys

def main():
    parser = argparse.ArgumentParser(description='HTML difference generator.')
    parser.add_argument('--pageload', help='pageload.json file to use.', type=str, nargs='?', default='')
    parser.add_argument('--results', help='Results file to write stats to.', type=str, nargs='?', default='successfulPageLoads.json')
    parser.add_argument('--domains', help='Domains file to look for.', type=str, nargs='?', default='grep_dom.json')
    args = parser.parse_args(sys.argv[1:])
    pageload_file = args.pageload
    results_file = args.results
    domains_file = args.domains
    browser_package_name = pageload_file.split("/")[-1]
    # We need pageload file to be specified.
    if pageload_file == '':
        print("Must supply pageload file with --pageload flag.")
        return
    print("Processing:", pageload_file)
    # First try loading pageload file.
    try:
        with open(pageload_file, "r") as inf:
            pageload_results = json.load(inf)
    except FileNotFoundError:
        print("Pageload file not found :/")
        return
    except json.decoder.JSONDecodeError:
        print("Error decoding pageload file :/")
        return
    # Load in previously saved results.
    saved_results = {}
    try:
        with open(results_file, "r") as inf:
            saved_results = json.load(inf)
    except json.decoder.JSONDecodeError:
        print("Invalid json found at: " + results_file + ", will be overwritten...")
    except FileNotFoundError:
        print("File", results_file, "not found, will create it and write...")
    # Load in domains we want to count.
    domains_to_count = []
    try:
        with open(domains_file, "r") as inf:
            domains_to_count = json.load(inf)
    except json.decoder.JSONDecodeError:
        print("Invalid json found at: " + domain + ", will be overwritten...")
    except FileNotFoundError:
        print("File", domains_file, "not found, will create it and write...")
    to_write = {} # JSON Stats to write.
    success_set = set()
    for request_url, stat in pageload_results.items():
        for domain in domains_to_count:
            if domain in request_url and stat["result"]:
                success_set.add(domain)
    to_write["overlap_domains"] = list(success_set)
    saved_results[browser_package_name] = to_write
    with open(results_file, "w+") as outfile:
        try:
            json.dump(saved_results, fp=outfile, sort_keys=True, indent=2)
        except:
            print("Error dumping json to results file.")
            return
    print("Done writing results.")

if __name__ == "__main__":
    main()
