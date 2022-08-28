#!/usr/bin/env python3
import json
import sys
from collections import defaultdict
import os
import matplotlib.pyplot as plt
import csv
import hashlib
import re

# FILE OPERATIONS
F_READ = "FSE_STAT_CHANGED"
F_WRITE = "FSE_CONTENT_MODIFIED"
F_DELETE = "FSE_DELETED"
F_RENAME = "FSE_RENAME"

def main():
    # We need some paths to compute this.
    OUT_DIR = "./combined_stats/"
    FILE_SHARERS = OUT_DIR + "file_shares.json"
    PII_LIST = "json/grep_pii.json"
    APKS_JSON = "apk_scripts/apks.json"

    if len(sys.argv) < 2:
        print("Please provide at least 1 path to process .fsmon files from.")
        return
    else:
        stat_paths = sys.argv[1:]
    stat_files = set()
    for p in stat_paths:
        stat_files.update(get_files_from_path(p + '/logs/', ".fsmon"))
    print("Found", len(stat_files), "in all paths provided.")
    # Things to track
    all_files_seen = defaultdict(list)
    pii_search_files = set()
    # Track number of UAs we observe.
    for stat_file in stat_files:
        filename = stat_file.split("/")[-1]
        package_hash = "-".join(filename.split("-")[0:2])
        package = package_hash.split("-")[0]
        with open(stat_file, "r") as inf:
            for line in inf.readlines():
                if "FSE_" not in line:
                    continue
                try:
                    current_update = json.loads(line)
                except json.JSONDecodeError:
                    print("Line in ", stat_file, "corrupted? o.O")
                all_files_seen[current_update["filename"]].append(package_hash)
                sdcardBase = "/".join(stat_file.split("/")[:-3])
                pii_search_files.add(sdcardBase + current_update["filename"])
    # Print pii found in paths
    with open(PII_LIST, "r") as inf:
        pii_to_search_for = json.load(inf)
    # Process apks file
    apks_processed = {}
    with open(APKS_JSON, "r") as apks_json:
        apks = json.load(apks_json)
        for apk in apks:
            pack_hash = apk["package_name"] + "-" + apk["app_hash"]
            apks_processed[pack_hash] = apk
    print_files = look_for_pii(pii_search_files, pii_to_search_for)
    for k, v in all_files_seen.items():
        all_files_seen[k] = list(set(v))
    with open(FILE_SHARERS, "w") as ouf:
        json.dump(all_files_seen, sort_keys=True, indent=2, fp=ouf)
    all_files_seen = sorted(all_files_seen.items(), key=lambda x: len(reduceToPacks(x[1])), reverse=True )
    # Print #apps, #packs for each id we look for.
    print("UA ID Stats: ID, # Apps, # Packs")
    markets = {
        "play": defaultdict(set),
        "pre": defaultdict(set),
        "alt": defaultdict(set)
    }
    pii_found = defaultdict(set)
    errors = set()
    for k, v in all_files_seen:
        if k in print_files:
            print(k, "&", len(set(v)), "&", len(reduceToPacks(v)), print_files[k])
            for pii_hit in print_files[k]:
                pii_found[pii_hit].update(v)
                for pack_hash in v:
                    pack_hash = pack_hash[:-6]
                    try:
                        m = get_market(apks_processed[pack_hash])
                        markets[m][pii_hit].add(pack_hash)
                    except KeyError:
                        errors.add(pack_hash)
    tot_set = set()
    print(markets)
    for k, v in pii_found.items():
        tot_set.update(v)
        print(k + "," +str(len(v)) + "," + str(len(reduceToPacks(v))), end="")
        for m in ["play", "pre", "alt"]:
            tmp = markets[m][k]
            print("," + str(len(tmp)) + "," + str(len(reduceToPacks(tmp))), end="")
        print("")
    print(tbf("Total") + ","
          + tbf(len(tot_set)) + ","
          + tbf(len(reduceToPacks(tot_set))), end="")
    for m in ["play", "pre", "alt"]:
        tmp = combine_dict(markets[m])
        print("," + tbf(len(tmp)) + "," + tbf(len(reduceToPacks(tmp))), end="")
    print()
    tot_out = set()
    for t in tot_set:
        tot_out.add(t[:-6])
    with open("combined_stats/file_leakers.json", "w") as ouf:
        json.dump(list(tot_set), ouf)

def tbf(s):
    return "\\textbf{" + str(s) + "}"

def combine_dict(d):
    ret_set = set()
    for k, v in d.items():
        ret_set.update(v)
    return ret_set

def get_market(apk):
    market = apk["market"]
    if "gplay" in market or "latest" in market or "play.google.com" in market:
        return "play"
    if "preinstalled" in market:
        return "pre"
    return "alt"

def look_for_pii(filepaths, piis):
    file_pii_map = defaultdict(set)
    print_files = defaultdict(set)
    # print("Paths:", filepaths)
    # print("PIIs:", piis)
    files_read =0
    errors = 0
    for filepath in filepaths:
        log = False
        try:
            with open(filepath, "r") as inf:
                filecontent = inf.read()
        except FileNotFoundError:
            if log:
                print("Not found", filepath)
            errors += 1
            continue
        except IsADirectoryError:
            if log:
                print("Is a dir", filepath)
            errors += 1
            continue
        except UnicodeDecodeError:
            if log:
                print("Decode", filepath)
            errors += 1
            continue
        files_read += 1
        for pii, category in piis.items():
            if "imei" in category:
                category = "imei"
            if ignore_category(category):
                continue
            if log:
                print("Searching", pii)
                print("Content..", filecontent)
            if advanceSearch(pii, filecontent):
                file_pii_map[filepath].add(category)
    print("Read:", files_read, "Errors:", errors)
    for k, v in file_pii_map.items():
        filename = k.split("/")
        index = filename.index("sdcard")
        filename = "/" + "/".join(filename[index:])
        print_files[filename] = v
        print(k, v)
    return print_files

def ignore_category(c):
    if c == "misc":
        return True
    elif c == "location_info":
        return True
    elif c == "os_info":
        return True
    elif c == "screen_info":
        return True
    elif c == "contact_info":
        return True
    return False

def advanceSearch(searchString, string):
    # Does a bunch of things to string and searches for it in the file.
    found = False
    smd5 = hashlib.md5(searchString.encode()).hexdigest()
    ss1 = hashlib.sha1(searchString.encode()).hexdigest()
    ss224 = hashlib.sha224(searchString.encode()).hexdigest()
    ss256 = hashlib.sha256(searchString.encode()).hexdigest()
    if re.search(searchString, string, re.IGNORECASE):
        found = True
    elif re.search(smd5, string, re.IGNORECASE):
        found = True
    elif re.search(ss1, string, re.IGNORECASE):
        found = True
    elif re.search(ss224, string, re.IGNORECASE):
        found = True
    elif re.search(ss256, string, re.IGNORECASE):
        found = True
    if ":" in searchString or "-" in searchString:
        searchString = searchString.replace(":", "")
        searchString = searchString.replace("-", "")
        return (found | advanceSearch(searchString, string))
    return found

def reduceToPacks(pack_hashs):
    packs = set()
    for pack_hash in pack_hashs:
        packs.add(pack_hash.split("-")[0])
    return packs

def get_files_from_path(path, extension):
    retset = set()
    for f in os.listdir(path):
        if f.endswith(extension):
            retset.add(path + "/" + f) # Need to track path as well
    return retset

# Boilerplate
if __name__ == "__main__":
    main()
