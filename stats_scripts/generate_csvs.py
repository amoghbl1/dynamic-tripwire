#!/usr/bin/env python3
import json
import csv
import sys
from collections import defaultdict
import matplotlib.pyplot as plt
import os
from adblockparser import AdblockRules

HOSTS_MIN_THRESHOLD = 1
HOSTS_MAX_THRESHOLD = 10000
HISTORY_LEAKER_THRESHOLD = 7
pii_maps = None
apks = None

all_test_set = set()
pii_leak_dict = defaultdict(dict)
easylist_allowed = defaultdict(int)

# Helper files
GREP_PII="json/grep_pii.json"
APKS_JSON="apk_scripts/apks.json"
EASY_LIST = "./json/easylist.txt"
EASY_PRIVACY = "./json/easyprivacy.txt"

easylist_rules = None
easyprivacy_rules = None
quick_match_easylist = set()
quick_match_easyprivacy = set()

OUT_DIR="./combined_stats/"

CATEGORY_HARM_SCORE = {
    "location_info": -2,
    # "os_info": -2,
    "Ad_id": -3,
    # "device_ip": -3,
    "device_mac": -5,
    "imei": -5,
    "wifi_mac": -5,
    "wifi_name": -5,
    "android_id": -5,
    "installed_packages": -5,
}

CATEGORY_HARM_GROUPED = {
    "location_info": "Location",
    "wifi_name": "Location",
    "wifi_mac": "Location",
    "Ad_id": "Resettable ID",
    "device_mac": "Non-resettable ID",
    "imei": "Non-resettable ID",
    "android_id": "Non-resettable ID",
    "installed_packages": "Installed Packages"
}

def main():
    # Setup out file variables
    if len(sys.argv) < 2:
        print("Supply 1 or more paths with cleanedStats files to produce results...")
        exit(1)
    ALL_CLEAN_STATS = sys.argv[1:]
    if not os.path.exists(OUT_DIR):
        os.makedirs(OUT_DIR)
    PII_HOSTS="pii_hosts.csv"
    PII_HOSTS_EXTENDED="pii_hosts_extended.csv"
    PII_HOSTS_DETAILED="pii_hosts_detailed.csv"
    MISC_DETAILS="misc_details.csv"
    MISC_HOSTS="misc_hosts.csv"
    HISTORY_CDF="history_cdf.pdf"
    HISTORY_GROUPED_CDF="history_grouped_cdf.pdf"
    HISTORY_DOMAIN="history_end_host.csv"
    HISTORY_FEATURE="history_feature_end_host.csv"
    HISTORY_LEAK_HARM="history_leak_harm.json"
    PAGELOAD_CDF="pageload_cdf.pdf"
    PII_HOSTS = OUT_DIR + PII_HOSTS
    PII_HOSTS_EXTENDED = OUT_DIR + PII_HOSTS_EXTENDED
    PII_HOSTS_DETAILED = OUT_DIR + PII_HOSTS_DETAILED
    MISC_DETAILS = OUT_DIR + MISC_DETAILS
    MISC_HOSTS = OUT_DIR + MISC_HOSTS
    HISTORY_CDF = OUT_DIR + HISTORY_CDF
    HISTORY_GROUPED_CDF = OUT_DIR + HISTORY_GROUPED_CDF
    HISTORY_DOMAIN = OUT_DIR + HISTORY_DOMAIN
    HISTORY_LEAK_HARM = OUT_DIR + HISTORY_LEAK_HARM
    HISTORY_FEATURE = OUT_DIR + HISTORY_FEATURE
    PAGELOAD_CDF = OUT_DIR + PAGELOAD_CDF
    # Setup globals
    setup_globals()
    # Load in all stats from
    all_stats = get_all_stats(sys.argv[1:])
    # Ready to process some stats.
    global all_test_set
    pii_store = defaultdict(set)
    host_pii_app_map = defaultdict(lambda: defaultdict(set))
    host_app_pii_map = defaultdict(lambda: defaultdict(set))
    misc_details = defaultdict(lambda: [0, set()])
    misc_packs = set()
    extraDataList = []
    hist_apk_ctr = 0
    goog_ctr = 0
    hist_set = set()
    one_host = set()
    mul_host = set()
    all_pack = set()
    all_apk = set()
    domain_cdf_helper = defaultdict(int)
    domain_cdf_grouped = defaultdict(int)
    domain_apk_sets = defaultdict(set)
    domain_apk_feat_sets = defaultdict(set)
    pageload_cdf_helper = defaultdict(int)
    pageload_pack = set()
    page_load_zero = set()
    pageload_entire = set()
    pageload_missed = defaultdict(set)
    global pii_leak_dict
    global easylist_allowed
    hl_ups = {}
    loaded_one = set()
    history_leaker_scores = {}
    for pack_hash, these_stats in all_stats.items():
        pack = pack_hash.split("-")[0]
        successful_pageloads = []
        missing_pageloads = []
        try:
            successful_pageloads = these_stats["overlap"]
            missing_pageloads = these_stats["missing"]
            # print(len(successful_pageloads))
        except KeyError:
            # print("Overlap keyerror for", pack_hash)
            pass
        if len(successful_pageloads) == 0:
            page_load_zero.add(pack_hash)
        if len(successful_pageloads) / these_stats["domains"] > 0.5:
            pageload_entire.add(pack_hash)
        if len(missing_pageloads) == 1:
            for p in missing_pageloads:
                pageload_missed[p].add(pack_hash)
        if len(successful_pageloads) > 0:
            loaded_one.add(pack_hash)
        all_pack.add(pack)
        all_apk.add(pack_hash)
        pii_log = these_stats["pii_log"]
        hist_log = flipHistoryLog(these_stats["history_log"])
        pageload_cdf_helper[len(successful_pageloads)] += 1
        leaked_domains = get_all_leaked_domains(hist_log)
        leaked_endpoint = set()
        feature_flag = True
        leak_score = 0
        success_and_leak = list(set((successful_pageloads + list(leaked_domains))))
        if len(successful_pageloads) > 0 and \
                len(leaked_domains) / len(success_and_leak) > 0:
            leak_score = len(leaked_domains) / len(success_and_leak)
            history_leaker_scores[pack_hash] = {"History Leak": leak_score * -1}
        if leak_score > 0.5:
            domain_cdf_helper[len(leaked_domains)] += 1
            # print("Hist uploader:", pack_hash)
            all_test_set.add(pack_hash)
            if pack in hl_ups:
                if len(set(hist_log)) > len(hl_ups[pack]):
                    hl_ups[pack] = list(set(hist_log))
            else:
                hl_ups[pack] = list(set(hist_log))
            if len(hist_log) > 1:
                mul_host.add(pack)
                for endpoint, domains_leaked in hist_log.items():
                    for domain in domains_leaked:
                        leaked_domains.add(domain)
                        if is_feature_endpoint(endpoint) and no_pii_to_endpoint(endpoint, pii_log):
                            domain_apk_feat_sets[endpoint].add(pack_hash)
                        else:
                            feature_flag = False # Plot in CDF
                            domain_apk_sets[endpoint].add(pack_hash)
                    leaked_endpoint.add(endpoint)
            else:
                one_host.add(pack)
                for endpoint, domains_leaked in hist_log.items():
                    if is_feature_endpoint(endpoint):
                        domain_apk_feat_sets[endpoint].add(pack_hash)
                    else:
                        feature_flag = False # Plot in CDF
                        domain_apk_sets[endpoint].add(pack_hash)
                    leaked_endpoint.add(endpoint)
                    for domain in domains_leaked:
                        leaked_domains.add(domain)
            hist_apk_ctr += 1
            hist_set.add(pack)
            # Also plot grouped cdf
            if len(successful_pageloads) > 0:
                leaked = len(leaked_domains) / len(successful_pageloads)
            else:
                leaked = 0
            # if leaked > 1:
            #     print("Leaked:", leaked)
            if not feature_flag and leaked > domain_cdf_grouped[pack]:
                domain_cdf_grouped[pack] = leaked
        extraDataList.append(these_stats["new_requests_size"])
        if len(pii_log) > 0:
            all_test_set.add(pack_hash)
        for pii_identifier, endpoints in pii_log.items():
            category = getPiiCategory(pii_identifier)
            tracker_endpoints = get_trackers_from_endpoints(endpoints)
            pii_store[category].add(pack_hash) # Store package names to be combined later.
            for h in pii_log[pii_identifier]:
                host_app_pii_map[h][pack_hash].add(getPiiCategory(pii_identifier))
                host_pii_app_map[h][pii_identifier].add(pack_hash)
            # Track more misc specific information here.
            if category == "misc":
                # Track unique packages and number of domains it gets uploaded to.
                misc_details[pii_identifier][0] += 1
                misc_details[pii_identifier][1].update(pii_log[pii_identifier])
                misc_packs.add(pack_hash)
            # Score the leakage in the pii_leak_dict
            elif category in CATEGORY_HARM_SCORE:
                value = CATEGORY_HARM_SCORE[category]
                pii_leak_dict[pack_hash][category] = value # * len(tracker_endpoints)

    print("Writing history leak scores to harm file:", HISTORY_LEAK_HARM)
    with open(HISTORY_LEAK_HARM, "w") as ouf:
        json.dump(history_leaker_scores, sort_keys=True, indent=2, fp=ouf)
    print("$$$$$$$$$$$$$$$$$")
    print("Pageladzero:", len(page_load_zero))
    print("$$$$$$$$$$$$$$$$$")
    print("PageloadEntire:", len(pageload_entire), len(pageload_entire) / len(all_apk))
    print("Pageload At least one:", len(loaded_one))
    with open("loadedOne", "w") as ouf:
        json.dump(list(loaded_one), fp=ouf, sort_keys=True, indent=2)
    print("Pages missed:", len(pageload_missed))
    print("Allset:", len(all_apk), len(reduceToPacks(all_apk)))
    print("Total:", len(all_apk.union(page_load_zero)), len(reduceToPacks(all_apk.union(page_load_zero))))
    print_all_test_stats()

    # Write history uploaders for cleaning
    with open("historyUploaders.json", "w") as ouf:
        json.dump(hl_ups, sort_keys=True, indent=2, fp=ouf)

    # Write pageload cdf
    writeCDF(pageload_cdf_helper, PAGELOAD_CDF, "Number of pages successfully loaded")

    # Construct grouped cdf helper
    domain_cdf_grouped_helper = defaultdict(int)
    for pack in reduceToPacks(all_stats.keys()):
        # Defaultdict should just handle this call
        domain_cdf_grouped_helper[domain_cdf_grouped[pack]] += 1

    # Fix location sets:
    host_pii_app_map = fix_dependent_pii(host_pii_app_map)

    # Sort some stuff
    pii_store = sorted(pii_store.items(), key=lambda x: len(reduceToPacks(x[1])), reverse=True)
    host_pii_app_map = sorted(host_pii_app_map.items(), key=getHostsTotal, reverse=True)
    tmp_dict = {}
    for k, v in host_pii_app_map:
        v_new = set()
        for k1, v1 in v.items():
            v_new = v_new.union(v1)
        tmp_dict[k] = list(v_new)
    with open("host_pii_app_map.json", "w") as ouf:
        json.dump(tmp_dict, sort_keys=True, indent=2, fp=ouf)
    misc_details = sorted(misc_details.items(), key=lambda x: x[1][0], reverse=True)
    # Write pii leaked per store.
    write_pii_type_store(pii_store)
    print("Writing pii hosts files with min:", HOSTS_MIN_THRESHOLD, "and max:", HOSTS_MAX_THRESHOLD)
    with open(PII_HOSTS, "w") as pii_host_csv, open(PII_HOSTS_EXTENDED, "w") as pii_host_extended, open(PII_HOSTS_DETAILED, "w") as pii_host_detailed:
        # Lets get the right field names, ignore 0 ones.
        fn_low = set()
        fn_reg = set()
        fn_hig = set()
        for k, d in host_pii_app_map:
            hostsTotal = getHostsTotal(("", d)) # Hack to make fn compatible
            if hostsTotal <= HOSTS_MIN_THRESHOLD:
                for l, v in d.items():
                    fn_low.add(getPiiCategory(l))
            elif hostsTotal <= HOSTS_MAX_THRESHOLD:
                for l, v in d.items():
                    fn_reg.add(getPiiCategory(l))
            else:
                for l, v in d.items():
                    fn_hig.add(l)
        fn_low = ["host"] + list(fn_low) + ["total"]
        fn_reg = ["host"] + list(fn_reg) + ["total"]
        fn_hig = ["host"] + list(fn_hig) + ["total"]
        writer_low = csvDictSetup(pii_host_extended, fn_low)
        writer_reg = csvDictSetup(pii_host_csv, fn_reg)
        writer_hig = csvDictSetup(pii_host_detailed, fn_hig)
        # Summary line stats
        totalsLine = defaultdict(set)
        # Extended file just gets its own total.
        extendedTotalsLine = defaultdict(set)
        # Last totals line, for detailed list.
        detailedTotalsLine = defaultdict(set)
        min_ctr = 0
        mid_ctr = 0
        max_ctr = 0
        for k, v in host_pii_app_map:
            hostsTotal = getHostsTotal(("", v)) # Hack to make fn compatible
            totalsLine["total"].update(getPackSet(v)) # Track packages, not just their counts for domains.
            justDict = {"host": k, "total": hostsTotal}
            justDict.update(reduceToNumbers(v))
            # Update totals for main table.
            for i, j in v.items():
                totalsLine[i].update(j)
            # Either add stats to the main one, extended one, or detailed one.
            if hostsTotal <= HOSTS_MIN_THRESHOLD:
                # print("Adding to min:", k)
                min_ctr += 1
                writer_low.writerow(dict(filter(lambda x: x[0] in fn_low, justDict.items())))
            elif hostsTotal <= HOSTS_MAX_THRESHOLD:
                # print("Adding to mid:", k)
                mid_ctr += 1
                # Let's track a separate totals line for just the medium range
                extendedTotalsLine["total"].update(getPackSet(v))
                writer_reg.writerow(dict(filter(lambda x: x[0] in fn_reg, justDict.items())))
                # Update totals line for this set.
                for i, j in v.items():
                    extendedTotalsLine[i].update(j)
            else:
                # print("Adding to max:", k)
                max_ctr += 1
                justDict = {"host": k, "total": hostsTotal}
                justDict.update(reduceToNumbers(v, False))
                writer_hig.writerow(dict(filter(lambda x: x[0] in fn_hig, justDict.items())))
                for i, j in v.items():
                    detailedTotalsLine[i].update(j)
        writer_reg.writerow(fixTotalsLine(totalsLine, fn_reg))
        writer_low.writerow(fixTotalsLine(extendedTotalsLine, fn_low))
        detailedTotalsLine = reduceToNumbers(dict(filter(lambda x: x[0] in fn_hig, extendedTotalsLine.items())), False)
        detailedTotalsLine["host"] = "Totals"
        writer_hig.writerow(textbf(detailedTotalsLine))
        print("Done writing pii leak stats: min", min_ctr, "mid", mid_ctr, "max", max_ctr)
    # Write the misc maps
    print("Writing", MISC_DETAILS)
    with open(MISC_DETAILS, "w") as misc_details_csv:
        misc_det_writer = csvDictSetup(misc_details_csv, ["misc", "packages", "hosts"])
        tothost = set()
        for k, v in misc_details:
            tothost.update(list(v[1]))
            misc_det_writer.writerow({"misc": k, "packages": v[0], "hosts": len(v[1])})
        misc_det_writer.writerow(textbf({"misc": "Totals", "packages": len(misc_packs), "hosts": len(tothost)}))
    # Write the history CDF image.
    print("Writing history leak CDF:", HISTORY_CDF)
    writeCDF(domain_cdf_helper, HISTORY_CDF, "Number of domains leaked")
    # Write history grouped CDF image.
    print("Writing history leak grouped CDF:", HISTORY_GROUPED_CDF)
    # Drop the 0 ones
    del domain_cdf_grouped_helper[0]
    if len(domain_cdf_grouped_helper) > 0:
        writeCDFFloat(domain_cdf_grouped_helper, HISTORY_GROUPED_CDF, "Percentage of domains loaded leaked")
    print("Writing history uploaded to domain counts:", HISTORY_DOMAIN, "and", HISTORY_FEATURE)
    writeHistDomainCounts(host_app_pii_map, domain_apk_sets, domain_apk_feat_sets, HISTORY_DOMAIN, HISTORY_FEATURE)
    # print("Sorted extra data:", sorted(extraDataList, reverse=True))
    print("One host, mult host:", len(one_host), len(mul_host))
    print_processed_data_stats(all_stats, hist_apk_ctr, hist_set, all_pack, all_apk)

def setup_globals():
    # Load in grep pii list to map categories.
    global pii_maps
    global apks
    global easylist_rules
    global easyprivacy_rules
    with open(GREP_PII, "r") as inf:
        pii_maps = json.load(inf)
    with open(APKS_JSON, "r") as inf:
        apks = json.load(inf)
    with open(EASY_LIST, "r") as inf:
        raw_rules = []
        for l in inf.readlines():
            raw_rules.append(l.rstrip())
        easylist_rules = AdblockRules(raw_rules)
    with open(EASY_PRIVACY, "r") as inf:
        raw_rules = []
        for l in inf.readlines():
            raw_rules.append(l.rstrip())
        easyprivacy_rules = AdblockRules(raw_rules)

def get_trackers_from_endpoints(endpoints):
    return endpoints

def fix_dependent_pii(host_pii_app_map):
    return host_pii_app_map

def get_easylist_hits(requests):
    hits = set()
    global quick_match_easylist
    global easylist_rules
    for request in requests:
        if request in quick_match_easylist:
            hits.add(request)
        elif easylist_rules.should_block(request):
            hits.add(request)
            quick_match_easylist.add(request)
    return hits

def get_easyprivacy_hits(requests):
    hits = set()
    global quick_match_easyprivacy
    global easyprivacy_rules
    for request in requests:
        if request in quick_match_easyprivacy:
            hits.add(request)
        elif easyprivacy_rules.should_block(request):
            hits.add(request)
            quick_match_easyprivacy.add(request)
    return hits

def get_all_stats(paths):
    all_stats = {}
    CLEANED_STATS="cleanedStats.json"
    for clean_stats_dir in paths:
        with open(clean_stats_dir + "/" + CLEANED_STATS, "r") as clean_stats_file:
            print("Processing stats file", clean_stats_file)
            current_clean_stats = json.load(clean_stats_file)
            overlap = set(current_clean_stats.keys()).intersection(set(all_stats.keys()))
            if len(overlap) > 0:
                # print("Overlap of", len(overlap), len(reduceToPacks(overlap)), "detected for new stats:", clean_stats_dir)
                overlap_merged = {}
                for stat in overlap:
                    # Let's merge the two stats to get the most data
                    current_clean_stats[stat] = merge_stats(current_clean_stats[stat], all_stats[stat])
            all_stats.update(current_clean_stats)
    return all_stats

def no_pii_to_endpoint(endpoint, pii_log):
    for k, v in pii_log.items():
        if endpoint in v:
            return False
    return True

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

def textbf(d):
    ret_dict = {}
    for k, v in d.items():
        ret_dict[k] = "\\textbf{" + str(v) + "}"
    return ret_dict

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

def print_processed_data_stats(all_stats, hist_apk_ctr, hist_set, all_pack, all_apk):
    print("Processed Packages:", len(all_stats))
    print("Apps:", hist_apk_ctr, "Hist set:", len(hist_set), hist_set)
    global apks
    total_browsers = 0
    latest_versions = {}
    for apk in apks:
        pack_name = apk['package_name']
        version = apk['app_version']
        if pack_name in all_pack:
            total_browsers += 1
        if pack_name in latest_versions:
            if latest_versions[pack_name]['app_version'] < version:
                latest_versions[pack_name] = apk
        else:
            latest_versions[pack_name] = apk
    latest_passing = set()
    latest_covered = 0
    latest_tested = set()
    for pack_name, apk in latest_versions.items():
        pack = apk['package_name']
        pack_hash = apk['package_name'] + '-' + apk['app_hash']
        if pack_hash in all_apk:
            latest_covered += 1
            latest_tested.add(pack)
    latest_missing = list(latest_passing - latest_tested)
    print("Latest missed:", len(latest_missing))
    print("All pack:", len(all_pack), ", All version:", len(all_apk), "Latest covered for", latest_covered)
    print("Total browsers for packs we test:", total_browsers, "Total browsers we actually test:", len(all_apk))

def merge_stats(stat1, stat2):
    """ Return a merged stat of the two stats, to take a union of tests. """
    # Write all of stat1
    pii_log = {}
    pl1 = stat1["pii_log"]
    pl2 = stat2["pii_log"]
    for k, v in pl1.items():
        try:
            pii_log[k] = v + pl2[k]
        except KeyError:
            pii_log[k] = v
    # Write remaining of stat2
    for k in pl2.keys() - pl1.keys():
        pii_log[k] = pl2[k]

    # Write all of stat1
    history_log = {}
    hl1 = stat1["history_log"]
    hl2 = stat2["history_log"]
    for k, v in hl1.items():
        try:
            history_log[k] = v + hl2[k]
        except KeyError:
            history_log[k] = v
    # Write remaining of stat2
    for k in hl2.keys() - hl1.keys():
        history_log[k] = hl2[k]

    ol1 = []
    ol2 = []
    try:
        ol1 = stat1["overlap"]
        ol2 = stat2["overlap"]
    except KeyError:
        pass
    olr = list(set(ol1 + ol2))
    # Returning bigger of 2 new_req_size for now
    nrs = max(stat1["new_requests_size"], stat2["new_requests_size"])

    try:
        dlr = stat1["domains"] + stat2["domains"]
    except KeyError:
        dlr = 0
        print("Error merging two stats, stat doesn't contain domain length...")

    return {
        "history_log": history_log,
        "pii_log": pii_log,
        "new_requests_size": nrs,
        "overlap": olr,
        "domains": dlr,
        }

def is_feature_endpoint(endpoint):
    if "Suggest" in endpoint:
        return True
    elif "Search" in endpoint:
        return True
    elif "Certcheck" in endpoint:
        return True
    elif "Compatibility" in endpoint:
        return True
    elif "Sitecheck" in endpoint:
        return True
    elif "URLSafe" in endpoint:
        return True
    elif "Favicon" in endpoint:
        return True
    elif "Kiddoware" == endpoint:
        return True
    return False

def write_pii_type_store(pii_store):
    PII_TYPE = OUT_DIR + "pii_type_store.csv"
    # Get APK package data
    markets = {
        "play": defaultdict(set),
        "pre": defaultdict(set),
        "alt": defaultdict(set)
    }
    apks_processed = {}
    for apk in apks:
        pack_hash = apk["package_name"] + "-" + apk["app_hash"]
        apks_processed[pack_hash] = apk
    print("Writing", PII_TYPE, "and unique package counts.")
    errors = set()
    for k, v in pii_store:
        for pack_hash in v:
            try:
                apk = apks_processed[pack_hash]
            except KeyError:
                errors.add(pack_hash)
            m = get_market(apk)
            markets[m][k].add(pack_hash)
    print("errors:", errors)
    # Write all the PII results
    with open(PII_TYPE, "w") as pii_type_csv:
        fn = ["category", "play_brow", "play_pack", "pre_brow", "pre_pack",
              "alt_brow", "alt_pack", "all_brow", "all_pack"]
        pii_type_writer = csv.DictWriter(pii_type_csv, fieldnames=fn)
        pii_type_writer.writeheader()
        totset = set()
        for k, v in pii_store:
            row = {}
            row["category"] = k
            row["all_brow"] = len(v)
            row["all_pack"] = len(reduceToPacks(v))
            for s in ["play", "pre", "alt"]:
                tmp = markets[s][k]
                row[s + "_brow"] = len(tmp)
                row[s + "_pack"] = len(reduceToPacks(tmp))
            pii_type_writer.writerow(row)
            totset.update(v)
        total_row = {"category": "Total", "all_brow": len(totset), "all_pack": len(reduceToPacks(totset))}
        for k in ["play", "pre", "alt"]:
            tmp = combine_dict(markets[k])
            total_row[k+"_brow"] = len(tmp)
            total_row[k+"_pack"] = len(reduceToPacks(tmp))
        pii_type_writer.writerow(textbf(total_row))


def writeHistDomainCounts(pii_hosts, domain_apk_sets, domain_apk_feat_sets, out_file, out_file_2):
    all_history_leakers = set()
    all_history_leakers_with_pii = set()
    # Write domain apk sets to outfile 1
    with open(out_file, "w") as hist_dom_csv:
        hist_dom_writer = csvDictSetup(hist_dom_csv, ["company", "browsers", "packages", "android_id", "imei","screen_info","location_info", "Ad_id", "device_mac", "wifi_mac", "wifi_name", "device_ip", "installed_packages", "os_info"], delimiter=":")
        domain_apk_sets_sorted = sorted(domain_apk_sets.items(), key=lambda x: len(x[1]), reverse=True)
        total_line = defaultdict(set)
        for k, v in domain_apk_sets_sorted:
            all_history_leakers.update(v)
            pii_sent = defaultdict(set)
            for pack_hash in v:
                if pack_hash in pii_hosts[k]:
                    if len(pii_hosts[k][pack_hash]) > 0:
                        all_history_leakers_with_pii.add(pack_hash)
                    for pii_cat in pii_hosts[k][pack_hash]:
                        pii_sent[pii_cat].add(pack_hash)
                        total_line[pii_cat].add(pack_hash)
            row = {"company": k, "browsers": len(v), "packages": len(v)}
            for k1, v1 in pii_sent.items():
                pii_sent[k1] = len(v1)
            row.update(pii_sent)
            hist_dom_writer.writerow(row)
        for k, v in total_line.items():
            total_line[k] = len(v)
        total_line["company"] = "Total"
        total_line["browsers"] = len(all_history_leakers)
        total_line["packages"] = len(reduceToPacks(all_history_leakers))
        hist_dom_writer.writerow(textbf(total_line))
    feature_hist_leakers = set()
    # Write domain apk feature sets to outfile 2
    with open(out_file_2, "w") as hist_feat_dom_csv:
        hist_feat_writer = csvDictSetup(hist_feat_dom_csv, ["company", "browsers", "packages"])
        domain_apk_feat_sets_sorted = sorted(domain_apk_feat_sets.items(), key=lambda x: len(x[1]), reverse=True)
        for k, v in domain_apk_feat_sets_sorted:
            feature_hist_leakers.update(v)
            hist_feat_writer.writerow({"company": k, "browsers": len(v), "packages": len(reduceToPacks(v))})
        hist_feat_writer.writerow(textbf({"company": "Total", "browsers": len(feature_hist_leakers), "packages": len(reduceToPacks(feature_hist_leakers))}))
    # Add temp hist leakers to the all set and write it to outfile 3
    all_history_leakers = all_history_leakers.union(feature_hist_leakers)
    print("##################################################################################")
    print("historyLeakers =", len(all_history_leakers))
    print("historyLeakersWithPII =", len(all_history_leakers_with_pii))
    print("historyLeakersFeatures =", len(feature_hist_leakers))
    print("##################################################################################")

def print_all_test_stats():
    global pii_leak_dict
    with open("combined_stats/file_leakers.json", "r") as inf:
        file_leakers = set(json.load(inf))
    html_modifiers = set()
    # with open("combined_stats/html_modifiers.json", "r") as inf:
    #     html_modifiers = set(json.load(inf))
    https_fails = get_https_fails_apps()
    insecure_ciphers = get_insecure_cipher_apps()
    https_defaults = get_https_default_apps()
    all_hits = (all_test_set.union(file_leakers.union(html_modifiers))).union(https_fails)
    print("######################################################################################")
    print("History + PII + SDcard + modifiers:", len(all_test_set), len(reduceToPacks(all_test_set)))
    print("PII Leak set", len(pii_leak_dict))
    print("HTTPS fail:", len(https_fails))
    print("######################################################################################")
    with open("combined_stats/all_test_browsers.json", "w") as ouf:
        json.dump(list(all_test_set), sort_keys=True, indent=2, fp=ouf)
    with open("combined_stats/pii_leak_harm.json", "w") as ouf:
        pii_leak_dict = normalize_category_harm_data(pii_leak_dict)
        json.dump(pii_leak_dict, sort_keys=True, indent=2, fp=ouf)
    with open("combined_stats/https_harm_protect.json", "w") as ouf:
        https_harm_protect = defaultdict(lambda: defaultdict(int))
        for app in https_fails:
            https_harm_protect[app]["TLS problem"] -= 1
        for app in insecure_ciphers:
            https_harm_protect[app]["TLS problem"] -= 1
        for app in https_defaults:
            https_harm_protect[app]["HTTPS default"] += 1
        json.dump(https_harm_protect, sort_keys=True, indent=2, fp=ouf)


def get_https_fails_apps():
    https_fails = set()
    all_apps_set = set()
    with open("combined_stats/allTestApps", "r") as inf:
        for l in inf.readlines():
            all_apps_set.add(l.rstrip())
    with open("combined_stats/certIgnoreApps", "r") as inf:
        for l in inf.readlines():
            app = l.rstrip()
            if app in all_apps_set:
                https_fails.add(app)
    return https_fails

def get_insecure_cipher_apps():
    insecure_cipher_apps = set()
    all_apps_set = set()
    with open("combined_stats/allTestApps", "r") as inf:
        for l in inf.readlines():
            all_apps_set.add(l.rstrip())
    with open("combined_stats/insecureCipherApps", "r") as inf:
        for l in inf.readlines():
            app = l.rstrip()
            if app in all_apps_set:
                insecure_cipher_apps.add(app)
    return insecure_cipher_apps

def get_https_default_apps():
    https_default_apps = set()
    all_apps_set = set()
    with open("combined_stats/allTestApps", "r") as inf:
        for l in inf.readlines():
            all_apps_set.add(l.rstrip())
    with open("combined_stats/httpsDefaultApps", "r") as inf:
        for l in inf.readlines():
            app = l.rstrip()
            if app in all_apps_set:
                https_default_apps.add(app)
    return https_default_apps

def normalize_category_harm_data(pii_leak_dict):
    ADD_HARM = False
    ret_dict = {}
    # Normalization factor
    max_harm_value = 0
    for pii, harm_value in CATEGORY_HARM_SCORE.items():
        max_harm_value += harm_value
    for pack_hash, category_value_map in pii_leak_dict.items():
        ret_dict[pack_hash] = {}
        # Get total bad score and normalize with max_harm_value
        current_harm_value = 0
        for category, value in category_value_map.items():
            current_harm_value += value
        normalized_harm = (current_harm_value / max_harm_value) * -1
        ret_dict[pack_hash] = {"PII Exposure": normalized_harm}
        """
        Use this if you need per category scores
        for category, value in category_value_map.items():
            if category in CATEGORY_HARM_GROUPED.keys():
                group = CATEGORY_HARM_GROUPED[category]
                if ADD_HARM and group in ret_dict[pack_hash]:
                    ret_dict[pack_hash][group] += value
                elif group in ret_dict[pack_hash]:
                    ret_dict[pack_hash][group] = max(value, ret_dict[pack_hash][group])
                else:
                    ret_dict[pack_hash][group] = value
            else:
                ret_dict[pack_hash][category] = value
        """
    return ret_dict

def writeCDFFloat(domain_cdf_helper, out_file, xlabel="X Label"):
    total_leakers = 0
    full_leakers = 0
    print("Domain cdf data:", domain_cdf_helper)
    for k, v in domain_cdf_helper.items():
        total_leakers += v
        if k >= 1:
            full_leakers += v
    moving_sum = 0
    cdf_x = [0]
    cdf_y = [0]
    max_domains_uploaded = max(domain_cdf_helper.keys()) + 1
    print("#############################################################################33333")
    print("Total leakers:", full_leakers/total_leakers, total_leakers)
    print(domain_cdf_helper)
    print("#############################################################################33333")
    prev = 0
    for i in sorted(domain_cdf_helper.keys()):
        moving_sum += prev
        prev = domain_cdf_helper[i]
        cdf_x.append(i) # We have the x axis to plot.
        cdf_y.append(moving_sum / total_leakers) # We have the y axis point.
    moving_sum += prev
    cdf_x.append(max(domain_cdf_helper.keys()))
    cdf_y.append(moving_sum/total_leakers)
    plot_setup()
    plt.step(cdf_x, cdf_y)
    plt.grid(linestyle=":")
    plt.yticks([0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    plt.xlim(left=-0.1, right=max_domains_uploaded)
    plt.ylim(bottom=0.0, top=1.1)
    plt.ylabel("CDF")
    plt.xlabel(xlabel)
    plt.savefig(out_file, dpi=2000)
    plt.close()
    # print("CDF(x, y)", cdf_x, cdf_y)
    print("Total leakers:", total_leakers)

def writeCDF(domain_cdf_helper, out_file, xlabel="X Label"):
    total_leakers = 0
    print("Domain cdf data:", domain_cdf_helper)
    for k, v in domain_cdf_helper.items():
        total_leakers += v
    moving_sum = 0
    cdf_x = [0]
    cdf_y = [0]
    max_domains_uploaded = max(domain_cdf_helper.keys()) + 1
    for i in range(0, max_domains_uploaded + 1):
        moving_sum += domain_cdf_helper[i - 1]
        cdf_x.append(i) # We have the x axis to plot.
        cdf_y.append(moving_sum / total_leakers) # We have the y axis point.
    plot_setup()
    plt.step(cdf_x, cdf_y)
    plt.grid(linestyle=":")
    plt.xticks(range(0, max_domains_uploaded))
    plt.yticks([0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    plt.xlim(left=-0.1, right=max_domains_uploaded)
    plt.ylim(bottom=0.0, top=1.1)
    plt.ylabel("CDF")
    plt.xlabel(xlabel)
    plt.savefig(out_file, dpi=2000)
    plt.close()
    # print("CDF(x, y)", cdf_x, cdf_y)
    print("Total leakers:", total_leakers)

def reduceToPacks(pack_hashs):
    packs = set()
    for pack_hash in pack_hashs:
        packs.add(pack_hash.split("-")[0])
    return packs


def fixTotalsLine(line, fn):
    line = dict(filter(lambda x: getPiiCategory(x[0]) in fn, line.items()))
    line = reduceToNumbers(line)
    line["host"] = "Total"
    return textbf(line)

def csvDictSetup(out_file, field_names, delimiter=","):
    writer = csv.DictWriter(out_file, field_names, delimiter=delimiter)
    writer.writeheader()
    return writer

def flipHistoryLog(hl):
    """ Take dom:host mapping and make it host:dom_list """
    ret = defaultdict(list)
    for k, v in hl.items():
        for i in v:
            ret[i].append(k)
    return ret

def get_all_leaked_domains(flipped_history_log):
    """ Flipped history log"""
    all_leaked_domains = set()
    for endpoint, leaked_domains in flipped_history_log.items():
        all_leaked_domains.update(leaked_domains)
    return all_leaked_domains

def getPiiCategory(pii):
    """ Return the category based on the loaded pii_grep json into pii_map """
    if pii == "host" or pii == "total":
        return pii
    try:
        if pii_maps[pii] == "imei_reduced":
            return "imei"
    except KeyError:
        return pii
    return pii_maps[pii]

def reduceToNumbers(d, convert=True):
    retd = {}
    convert_set = set()
    for k, v in d.items():
        if convert:
            category = getPiiCategory(k)
            if category in retd:
                retd[category].update(v)
            else:
                retd[category] = set(v)
        else:
            retd[k] = len(v)
    if convert:
        for k, v in retd.items():
            retd[k] = len(v)
    return retd

def getPackSet(d):
    retset = set()
    for k, v in d.items():
        retset.update(v)
    return retset

def getHostsTotal(hd):
    d = hd[1]
    # Return addition of length of all dict items.
    retset = set()
    for k, v in d.items():
        retset.update(v)
    return len(retset)

if __name__ == "__main__":
    main()
