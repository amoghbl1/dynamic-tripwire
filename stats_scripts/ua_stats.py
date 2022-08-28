#!/usr/bin/env python3
import json
import sys
from collections import defaultdict
import os
import matplotlib.pyplot as plt
from matplotlib_venn import venn3
import csv

def main():
    # We need some paths to compute this.
    UA_IDS = "json/ua_ids.json"
    OUT_DIR = "./combined_stats/"

    ALL_UAS_OUT = OUT_DIR + "allUAsSeen.txt"
    UNKNOWN_UAS = OUT_DIR + "uncategorizedUAs.txt"
    UA_CDF = OUT_DIR + "UA_cdf.pdf"
    UA_GROUPED_CDF = OUT_DIR + "UA_grouped_cdf.pdf"
    ENGINES_CSV = OUT_DIR + "browser_engines.csv"
    UA_VENN = OUT_DIR + "UA_venn.pdf"
    UA_GROUPED_VENN = OUT_DIR + "UA_grouped_venn.pdf"
    if len(sys.argv) < 2:
        print("Please provide at least 1 path to process .ua files from.")
        return
    else:
        ua_paths = sys.argv[1:]
    # Load in identifiers we need to look for.
    with open(UA_IDS, "r") as inf:
        ua_ids = json.load(inf)
    ua_files = set()
    for p in ua_paths:
        ua_files.update(get_files_from_path(p + '/logs/', ".ua"))
    print("Found", len(ua_files), "in all paths provided.")
    # Things to track
    # All UAs observed
    all_uas_seen = set()
    # Track matches to ids we look for.
    ua_ids_map = defaultdict(set)
    # UAs we manually categorize
    ua_category = defaultdict(set)
    uncategorized = set()
    # Track number of UAs we observe.
    uas_seen_map = defaultdict(int)
    uas_grouped_map = defaultdict(list)
    for ua_file in ua_files:
        package_hash = ua_file.split("/")[-1]
        ua_category["Total"].add(package_hash)
        package = package_hash.split("-")[0]
        with open(ua_file, "r") as inf:
            try:
                packets = json.load(inf)
            except json.JSONDecodeError:
                print("File", ua_file, "corrupted.")
            ua_set = set()
            for packet in packets:
                layers = packet["_source"]["layers"]
                if "http.user_agent" not in layers:
                    ua_category["Missing"].add(package_hash)
                else:
                    ua = layers["http.user_agent"][0]
                    all_uas_seen.add(ua)
                    ua_set.add(ua)
                    if ua == "":
                        ua_category["Blank"].add(package_hash)
                    elif "Firefox" in ua:
                        ua_category["Gecko"].add(package_hash)
                    elif "wv)" in ua:
                        ua_category["WebView"].add(package_hash)
                    elif "Chrome" in ua:
                        ua_category["Chrome"].add(package_hash)
                    elif "Presto" in ua or "OPR/" in ua:
                        ua_category["Opera"].add(package_hash)
                    elif "Android" in ua and ("AppleWebKit" in ua or "AppleWebkit" in ua) and "KHTML" in ua:
                        ua_category["Chromelike"].add(package_hash)
                    elif "android" in ua and "applewebkit" in ua and "KHTML" in ua:
                        ua_category["Chromelike"].add(package_hash)
                    else:
                        ua_category["Uncategorized"].add(package_hash)
                        uncategorized.add(ua)
                    for ua_id in ua_ids.keys():
                        if ua_id in ua:
                            id_category = ua_ids[ua_id]
                            ua_ids_map[id_category].add(package_hash)
            # Add ua set length
            uas_seen_map[len(ua_set)] += 1
            if len(ua_set) > 10:
                print("Over 10:", package_hash)
            uas_grouped_map[package].append(len(ua_set))
    # Dump all User Agents we see.
    with open(ALL_UAS_OUT, "w") as outfile:
        for i in all_uas_seen:
            outfile.write(i + "\n")
    # Dump unknown UAs.
    with open(UNKNOWN_UAS, "w") as outfile:
        for i in uncategorized:
            outfile.write(i + "\n")
    write_ua_category_stats(ua_category, ENGINES_CSV, UA_GROUPED_VENN, UA_VENN)
    # Print #apps, #packs for each id we look for.
    ua_ids_map = sorted(ua_ids_map.items(), key=lambda x: len(reduceToPacks(x[1])), reverse=True)
    print("UA ID Stats: ID, # Apps, # Packs")
    for k, v in ua_ids_map:
        print(k, len(v), len(reduceToPacks(v)))
        if k == "IMEI":
            print(v)
    # Save UA CDF to png
    write_CDF(uas_seen_map, UA_CDF, "Number of User-Agent strings used by a browser")
    # Averaged UA len CDF
    uas_grouped_map_cdf = defaultdict(int)
    for k, v in uas_grouped_map.items():
        avg = sum(v) / len(v)
        avg = round(avg)
        uas_grouped_map_cdf[avg] += 1
    write_CDF(uas_grouped_map_cdf, UA_GROUPED_CDF, "Number of User-Agent strings used by a browser")

def plot_setup():
    plt.rcParams['axes.labelsize'] = '7'
    plt.rcParams['axes.titlesize'] = '7'
    plt.rcParams['lines.linewidth'] = '1'
    plt.rcParams['xtick.labelsize'] = '7'
    plt.rcParams['ytick.labelsize'] = '7'
    plt.rcParams['grid.color'] = 'gray'
    plt.rcParams['grid.linestyle'] = ':'
    plt.rcParams['grid.linewidth'] = 0.75
    plt.rcParams['patch.force_edgecolor'] = True
    plt.rcParams['patch.facecolor'] = 'b'
    # plt.rcParams['xtick.direction'] = 'in'
    # plt.rcParams['ytick.direction'] = 'in'
    plt.rcParams['xtick.major.size'] = '3'
    plt.rcParams['ytick.major.size'] = '3'
    plt.rcParams['xtick.major.width'] = '0.5'
    plt.rcParams['ytick.major.width'] = '0.5'
    fig = plt.figure(figsize=(3.12561, 1.6))
    fig.set_tight_layout({"pad": 0, "rect": [0, 0, 1, 1]})
    ax = fig.add_subplot(111)
    # Plot stuff
    plt.tight_layout()

def write_ua_category_stats(ua_cat, out_file, venn1, venn2):
    # Exclusively uncategorized ?
    valid_match = set()
    for c in ["Gecko", "WebView", "Chrome", "Chromelike", "Opera"]:
        valid_match.update(ua_cat[c])
    # ua_cat["Uncategorized"] -= valid_match
    # ua_cat["Blank"] -= valid_match
    # ua_cat["Blank"] -= ua_cat["Uncategorized"]
    blank_only = ua_cat["Blank"] - valid_match - ua_cat["Uncategorized"]
    if len(blank_only) > 0:
        print("Blank only:", blank_only)

    # Plot a couple of venns
    plot_setup()
    # Grouped into packs
    wv_venn = reduceToPacks(ua_cat["WebView"])
    ch_venn = reduceToPacks(ua_cat["Chrome"].union(ua_cat["Chromelike"]))
    un_venn = reduceToPacks(ua_cat["Uncategorized"])
    venn3([wv_venn, ch_venn, un_venn], ("WebView", "Chrome (like)", "Unknown UA"))
    plt.savefig(venn1, dpi=2000)
    plt.close()
    # Ungrouped venn, raw apps.
    wv_venn = ua_cat["WebView"]
    ch_venn = ua_cat["Chrome"].union(ua_cat["Chromelike"])
    un_venn = ua_cat["Uncategorized"]
    venn3([wv_venn, ch_venn, un_venn], ("WebView", "Chrome (like)", "Unknown UA"))
    plt.savefig(venn2,dpi=2000)
    plt.close()


    # Print some agg stuff
    s = set()
    for c in ["WebView", "Chrome", "Chromelike"]:
        s.update(ua_cat[c])
    s = reduceToPacks(s)
    print("WV + Chrome + Chromelike = ", len(s))

    # Write to the csv
    ua_cat = sorted(ua_cat.items(), key=lambda x: len(reduceToPacks(x[1])), reverse=True)
    # Fix total which is now on top
    ua_cat = ua_cat[1:] + [ua_cat[0]]
    cols = ["engine", "apps", "packs", "percentage"]
    total_packs_with_ua_data = len(reduceToPacks(ua_cat[-1][1]))
    with open(out_file, "w") as outf:
        writer = csv.DictWriter(outf, cols)
        writer.writeheader()
        for row, apps in ua_cat:
            packs_count = len(reduceToPacks(apps))
            percentage = round((packs_count*100)/total_packs_with_ua_data, 2)
            entry = {"engine": row, "apps": len(apps), "packs": packs_count, "percentage": percentage}
            if row == "Total":
                entry = textbf(entry)
            writer.writerow(entry)

def get_files_from_path(path, extension):
    retset = set()
    for f in os.listdir(path):
        if f.endswith(extension):
            retset.add(path + "/" + f) # Need to track path as well
    return retset

def reduceToPacks(pack_hashs):
    packs = set()
    for pack_hash in pack_hashs:
        packs.add(pack_hash.split("-")[0])
    return packs

def textbf(d):
    ret_dict = {}
    for k, v in d.items():
        ret_dict[k] = "\\textbf{" + str(v) + "}"
    return ret_dict

def write_CDF(cdf_data, out_file, xlabel="Default x label."):
    cdf_total = 0
    print("CDF data:", cdf_data)
    for k, v in cdf_data.items():
        cdf_total += v
    moving_sum = 0
    cdf_x = [0]
    cdf_y = [0]
    max_datapoint = max(cdf_data.keys()) + 1
    for i in range(0, max_datapoint + 1):
        moving_sum += cdf_data[i - 1]
        cdf_x.append(i) # We have the x axis to plot.
        cdf_y.append(moving_sum / cdf_total) # We have the y axis point.
    plot_setup()
    plt.step(cdf_x, cdf_y)
    plt.grid(linestyle=":")
    plt.xticks(range(0, max_datapoint))
    plt.yticks([0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    plt.xlim(left=-0.1, right=max_datapoint)
    plt.ylim(bottom=0.0, top=1.1)
    plt.ylabel("CDF")
    plt.xlabel(xlabel)
    plt.savefig(out_file, dpi=2000)
    plt.close()
    # print("CDF(x, y)", cdf_x, cdf_y)
    print("Total CDF data:", cdf_total)

# Boilerplate
if __name__ == "__main__":
    main()
