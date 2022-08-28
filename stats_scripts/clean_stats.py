#!/usr/bin/env python3
import json
import sys
from collections import defaultdict
import os

BASELINE_STATS = {
    "history_log": {},
    "pii_log": {}
}
pii_maps = None
hosts_unmapped = []
HOSTNAME_PARENT_MAP="stats_scripts/hostname_parent.csv"
HOSTNAME_MISSED="stats_scripts/hostname_missed.txt"

BASELINE_STATS_POSTFIX = "com.homezoneproject.mywebviewapp"

def main():
    # Setup out file variables
    ALL_STATS="allStats.json"
    CLEANED_STATS="cleanedStats.json"
    GREP_PII="json/grep_pii.json"
    FIRST_PARTY_MAP="json/first_party.json"
    GREP_DOM="/grep_dom.json"
    ALLOW_LIST="/allowed_pii.json"
    OUT_DIR="./"
    global pii_maps
    global BASELINE_STATS
    global HOSTNAME_PARENT_MAP
    global HOSTNAME_MISSED
    if len(sys.argv) < 2:
        print("Assuming all stats file is in local dir, if not supply stats json path and retry!!")
    else:
        ALL_STATS = sys.argv[1] + "/" + ALL_STATS
        OUT_DIR = "/".join(ALL_STATS.split("/")[:-1]) + "/"
    GREP_DOM = OUT_DIR + GREP_DOM
    ALLOW_LIST  = OUT_DIR + ALLOW_LIST
    # Some directory setup
    if not os.path.exists(OUT_DIR):
        os.makedirs(OUT_DIR)
    CLEANED_STATS = OUT_DIR + CLEANED_STATS
    # Load in grep pii list to map categories.
    with open(GREP_PII, "r") as inf:
        pii_maps = json.load(inf)
    # Load in grep dom list.
    with open(GREP_DOM, "r") as inf:
        dom_set = set(json.load(inf))
    with open(ALLOW_LIST, "r") as inf:
        allow_maps = json.load(inf)
    print("Processing stats file:", ALL_STATS)
    # Load hostname to parent company map.
    host_parent_map = {}
    with open(HOSTNAME_PARENT_MAP, "r") as inf:
        tmp_map = [i.strip() for i in inf.readlines()]
        for i in tmp_map:
            host, parent = i.split(",")
            host_parent_map[host] = parent
    # Load package to first party name map.
    first_party_map = {}
    with open(FIRST_PARTY_MAP, "r") as inf:
        first_party_map = json.load(inf)
    with open(ALL_STATS, "r") as inf:
        all_stats = json.load(inf)
    pii_store = defaultdict(set)
    pii_hosts = defaultdict(lambda: defaultdict(list))
    misc_details = defaultdict(lambda: [0, set()])
    misc_packs = set()

    # Proceess the multiple baselines, combine, and set global variable
    all_stats = process_baseline_stats(all_stats, dom_set)

    cleaned_stats = {} # Stats we save after cleanup
    all_pack = set() # Tracks unique packages processed.
    all_apk = set() # Tracks unique apks (pack-hash) processed.
    for res in all_stats:
        resplit = res.split("-")
        pack = resplit[0]
        all_pack.add(pack)
        pack_hash = pack + "-" + resplit[1]
        all_apk.add(res)
        # We don't need to process the baseline in stats we collect.
        theseStats = all_stats[res]
        theseStats.update(cleanStats(theseStats, allow_maps))
        # Reduce stats to company, instead of random hosts.
        # theseStats.update(mapHostsToParents(theseStats, host_parent_map))
        # Removing baseline upload stats, identifiers that should have been sent to parties (based on the site itself).
        theseStats.update(removeBaselineStats(theseStats))
        # Remove all stats related to data uploaded to sites we visit, not just baseline.
        theseStats.update(removeVisitedDomains(theseStats, dom_set))
        # Remove misc stats, if other pii is present.
        theseStats = checkCategoryOnly(pack_hash, theseStats, "misc")
        # theseStats = checkCategoryOnly(pack_hash, theseStats, "os_info")
        # theseStats = checkCategoryOnly(pack_hash, theseStats, "Fingerprinting")
        # Remove unwanted stats.
        theseStats = sanatizeStats(theseStats)
        # Reduce overlap to overlap with doms we visit.
        theseStats["overlap"] = list(set(theseStats["overlap"]).intersection(dom_set))
        theseStats["missing"] = list(dom_set - set(theseStats["overlap"]))
        # Reduce stats to company, after cleaning.
        first_party_list = []
        if pack in first_party_map:
            first_party_list = first_party_map[pack]
        theseStats.update(mapHostsToParents(theseStats, host_parent_map, first_party_list))
        # Combine pii log latitude and longitude
        theseStats["pii_log"] = combine_latlon(theseStats["pii_log"])
        cleaned_stats[pack_hash] = theseStats
    # Lets save the cleaned stats to help combine multiple tests.
    with open(CLEANED_STATS, "w") as cleaned_stats_file:
        json.dump(cleaned_stats, sort_keys=True, indent=2, fp=cleaned_stats_file)
    print("Processed Packages:", len(cleaned_stats))
    print("All pack:", len(all_pack), ", All version:", len(all_apk))
    dumpUnmappedHots()
    print("Dumped unmapped hosts to ", HOSTNAME_MISSED)


def process_baseline_stats(all_stats, dom_set):
    # First process what was uploaded where by the baseline, in order to remove pii collected by the site itself.
    # e.g: chinalawandpolicy has a tracking pixel: pixel.wp.com
    ret_stats = {}
    # Initialize the baseline stat
    global BASELINE_STATS
    bhl = BASELINE_STATS["history_log"]
    bpl = BASELINE_STATS["pii_log"]
    for package, thisStat in all_stats.items():
        if BASELINE_STATS_POSTFIX not in package:
            ret_stats[package] = thisStat
            continue
        hl = thisStat["history_log"]
        pl = thisStat["pii_log"]
        for k, v in hl.items():
            if k in bhl:
                bhl[k].update(v.keys()) # Only process hosts, not requests.
            else:
                bhl[k] = set(v.keys())
        for k, v in pl.items():
            if k in bpl:
                bpl[k].update(v)
            else:
                bpl[k] = set(v)
        loaded_doms = list(set(thisStat["overlap"]).intersection(dom_set))
        if len(loaded_doms) != len(dom_set):
            print("BASELINE UNEVEN!!", len(loaded_doms)," RERUN?")
        # Lets look at company maps instead of just hosts.
        # BASELINE_STATS = mapHostsToParents(BASELINE_STATS, host_parent_map)
        # print("BASELINE:", BASELINE_STATS)
    return ret_stats

def get_super_stat(all_stats, dom_set):
    # Get a union of PII uploaded to the dom_set, in order to figure out all
    # data that is collected by a website
    ret_stats = {}
    hl = defaultdict(lambda: defaultdict(int))
    pl = defaultdict(lambda: defaultdict(int))
    for package, thisStat in all_stats.items():
        thl = thisStat["history_log"]
        tpl = thisStat["pii_log"]
        for k, v in thl.items():
            for u in v.keys():
                hl[k][u] += 1
        for k, v in tpl.items():
            for u in v:
                pl[k][u] += 1
    print("Super Stat HL:", hl)
    print("Super Stat PL:", pl)

def dumpUnmappedHots():
    global hosts_unmapped
    global HOSTNAME_MISSED
    dump_set = set(hosts_unmapped)
    with open(HOSTNAME_MISSED, "w") as out_file:
        for h in dump_set:
            out_file.write(h + ",\n")

def checkCategoryOnly(pack_hash, stats, category):
    """ Remove misc fields, if other pii exists, else do nothing. """
    pl = stats["pii_log"]
    other = False
    npl = {}
    for k, v in pl.items():
        if getPiiCategory(k) != category:
            other = True
            npl[k] = v
    if other:
        stats["pii_log"] = npl
    elif len(pl) > 0:
        print("#######################################################################################")
        print(category, " only:", pack_hash)
        print(pl)
        print("#######################################################################################")
    return stats

def sanatizeStats(stats):
    """ Remove stats that have been manually confirmed to be false positives and remove empties """
    pl = stats["pii_log"]
    npl = {}
    ignore_pii_categories = ["contact_info", "misc", "os_info", "screen_info"]

    for k, v in pl.items():
        if getPiiCategory(k) not in ignore_pii_categories:
            if len(v) > 0:
                npl[k] = v
            # Dropping 0 len pii logs.
    stats["pii_log"] = npl
    return stats

def getPiiCategory(pii):
    """ Return the category based on the loaded pii_grep json into pii_map """
    if pii == "host" or pii == "total":
        return pii
    try:
        return pii_maps[pii]
    except KeyError:
        return pii

def cleanStats(stats, allow_maps):
    """ Remove domain from domain in history_log """
    hl = stats["history_log"]
    pl = stats["pii_log"]
    # Also remove overlapping set of domains reached out to.
    overlap = set(stats["overlap"])
    newhl = {}
    newpl = {}
    # Load manual allow lists.
    allowed_hl = allow_maps["history_log"]
    allowed_pl = allow_maps["pii_log"]
    allowed_all = allow_maps["ALL"]
    # Remove mappings of history being uploaded to itself.
    for k, v in hl.items():
        v = set(v)
        try:
            v.remove(k)
        except KeyError:
            pass
        newhl[k] = list(v - overlap)
    # Manual history log cleanup
    for k, v in allowed_hl.items():
        v = set(v)
        if k in newhl:
            nhl_v = set(newhl[k])
            nhl_v -= v
            if len(nhl_v) > 0:
                # Load manual allow lists.
                newhl[k] = nhl_v
            else:
                del newhl[k]
    for k, v in pl.items():
        if k == "location" or k == "battery" or k == "volume" or k == "fingerprint" or k == "timezone":
            pass
        else:
            # Manual pii cleanup
            try:
                v = set(v) - set(allowed_pl[k]) - set(allowed_all)
            except KeyError:
                v = set(v) - set(allowed_all) # Unique entries
            newpl[k] = list(v - overlap)
    return {"history_log": newhl, "pii_log": newpl}

def combine_latlon(pl):
    newpl = {}
    # Process lat lon upload, only mark if both exist.
    if '42.3' in pl and '71.0' in pl:
        latlon = set(pl['42.3']).intersection(set(pl['71.0']))
        if len(latlon) > 0:
            newpl['processed_location_lat_lon'] = list(latlon)
    for k, v in pl.items():
        if k == '42.3' or k == '71.0':
            continue
        newpl[k] = v
    return newpl

def removeBaselineStats(stats):
    """ Remove baseline stats for history_log and pii_log, so as to only look for irregular behaviour. """
    hl = stats["history_log"]
    pl = stats["pii_log"]
    bhl = BASELINE_STATS["history_log"]
    bpl = BASELINE_STATS["pii_log"]
    newhl = {}
    newpl = {}
    for k, v in hl.items():
        v = set(v)
        try:
            v -= set(bhl[k])
        except KeyError:
            pass
        # Don't add empty lists to the history_log
        if len(v) > 0:
            newhl[k] = list(v)
    for k, v in pl.items():
        v = set(v)
        try:
            v -= set(bpl[k])
        except KeyError:
            pass
        newpl[k] = list(v)
    return {"history_log": newhl, "pii_log": newpl}

def removeVisitedDomains(stats, doms):
    """ Remove all stats uploaded to sites we visit as part of the test. """
    hl = stats["history_log"]
    pl = stats["pii_log"]
    newhl = {}
    newpl = {}
    for k, v in hl.items():
        newhl[k] = list(set(v) - doms)
    for k, v in pl.items():
        newpl[k] = list(set(v) - doms)
    return {"history_log": newhl, "pii_log": newpl}

def mapHostsToParents(stats, host_parent_map, first_party_list):
    """
    Reduce history_log and pii_log from hosts to companies.
    Also account for hosts being 1st or 3rd party, add a * if first.
    """
    global hosts_unmapped
    hl = stats["history_log"]
    pl = stats["pii_log"]
    newpl = {}
    newhl = {}
    for domain_uploaded, endpoint_requests in hl.items():
        new_values = set()
        for endpoint in endpoint_requests:
            if endpoint in host_parent_map:
                endpoint_service = host_parent_map[endpoint]
                if endpoint_service in first_party_list:
                    new_values.add(endpoint_service + "*")
                else:
                    new_values.add(endpoint_service)
            else:
                hosts_unmapped.append(endpoint)
                new_values.add(endpoint)
        newhl[domain_uploaded] = list(new_values)
    for pii_identifier, endpoints in pl.items():
        new_values = set()
        for endpoint in endpoints:
            if endpoint in host_parent_map:
                endpoint_service = host_parent_map[endpoint]
                if endpoint_service in first_party_list:
                    new_values.add(endpoint_service + "*")
                else:
                    new_values.add(endpoint_service)
            else:
                hosts_unmapped.append(endpoint)
                new_values.add(endpoint)
        newpl[pii_identifier] = list(new_values)
    return {"history_log": newhl, "pii_log": newpl}

if __name__ == "__main__":
    main()
