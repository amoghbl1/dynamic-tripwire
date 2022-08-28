#!/usr/bin/env python3
import json
import sys
import re
from collections import defaultdict
from adblockparser import AdblockRules
from multiprocessing import Pool

REQUESTS_HARM_PROTECT = "./combined_stats/requests_harm_protect.json"

EASY_LIST = "./json/easylist.txt"
EASY_PRIVACY = "./json/easyprivacy.txt"

allowed_html = None
easylist_rules = None
easyprivacy_rules = None

# Result keys
BLOCKING_MISSED = "Request blocking missed"

def main():
    # We need some paths to compute this.
    OUT_DIR = "./combined_stats/"
    REQUESTS_FILE = "/crawlRequests.json"
    if len(sys.argv) < 2:
        print("Please provide at least 1 path to process htmlDiffStats file from.")
        return
    all_stats = {}
    ctr = 0
    for i in sys.argv[1:]:
        ctr += 1
        with open(i + REQUESTS_FILE, "r") as inf:
            this_diff = json.load(inf)
            all_stats = merge_requests(all_stats, this_diff)
    setup_globals()
    global easylist_rules
    global easyprivacy_rules
    with Pool() as p:
        results = p.map(process_all_stats_piece, all_stats.items())
    # Reduce results
    reduced_dict = {}
    for pack_hash, scores_dict in results:
        reduced_dict[pack_hash] = scores_dict
    with open(REQUESTS_HARM_PROTECT, "w") as ouf:
        json.dump(
            normalize_blocking_scores(reduced_dict),
            sort_keys=True,
            indent=2,
            fp=ouf
        )
def process_all_stats_piece(pack_hash_stat):
    pack_hash, stat = pack_hash_stat
    print("Processing", pack_hash)
    ret_piece = {}
    crawl_requests = stat["crawl_requests"]
    easylist_hit, easylist_miss = \
        get_rules_hit_miss(easylist_rules, crawl_requests)
    easyprivacy_hit, easyprivacy_miss = \
        get_rules_hit_miss(easyprivacy_rules, crawl_requests)
    if len(easylist_hit) > 0 or len(easyprivacy_hit) > 0:
        print("Blocking missed:", len(easylist_hit), len(easyprivacy_hit))
        ret_piece[BLOCKING_MISSED] = \
            unionSets(easyprivacy_hit, easylist_hit)
    elif len(crawl_requests) > 0:
        print("Good browser:", pack_hash)
    return (pack_hash, ret_piece)

def setup_globals():
    global easylist_rules
    global easyprivacy_rules
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

def merge_requests(requests1, requests2):
    # Merge everything from 2 into 1, that way 1 has the combined stats.
    for k, v in requests2.items():
        if k not in requests1:
            requests1[k] = v
        else:
            browser_requests_1 = set(requests1[k]["browser_requests"])
            browser_requests_2 = set(requests2[k]["browser_requests"])
            crawl_requests_1 = set(requests1[k]["crawl_requests"])
            crawl_requests_2 = set(requests2[k]["crawl_requests"])
            requests1[k]["browser_requests"] = \
                list(browser_requests_1.union(browser_requests_2))
            requests1[k]["crawl_requests"] = \
                list(crawl_requests_1.union(crawl_requests_2))
    return requests1


def normalize_blocking_scores(blocking_scores):
    ret_dict = defaultdict(lambda: defaultdict(int))
    all_blocked_content = defaultdict(int)
    # Get normalization factor for each feature
    for pack_hash, blocking_score_dict in blocking_scores.items():
        for blocking_feature, blocked_content in blocking_score_dict.items():
            if len(blocked_content) > all_blocked_content[blocking_feature]:
                all_blocked_content[blocking_feature] = len(blocked_content)
    for pack_hash, blocking_score_dict in blocking_scores.items():
        for blocking_feature, blocked_content in blocking_score_dict.items():
            # Filter only stuff we want to write
            if blocking_feature == BLOCKING_MISSED:
                ret_dict[pack_hash][blocking_feature] = \
                    (len(blocked_content) / all_blocked_content[blocking_feature]) * -1
            else:
                print("Invalid blocking score feature found:", blocking_feature)
    return ret_dict

def get_rules_hit_miss(rules, entries):
    hit = set()
    miss = set()
    for entry in entries:
        if entry and rules.should_block(entry):
            hit.add(entry)
        else:
            miss.add(entry)
    return hit, miss

def reduceDictSet(dict_set):
    ret_dict = {}
    for k, v in dict_set.items():
        ret_dict[k] = list(v)
    return ret_dict

def reduceDictDictSet(dict_dict_set):
    ret_dict = {}
    for k, v in dict_dict_set.items():
        td = {}
        for k1, v1 in v.items():
            td[k1] = list(v1)
        ret_dict[k] = td
    return ret_dict

def reduceDictDictSet2(dict_dict_set):
    ret_dict = {}
    for k, v in dict_dict_set.items():
        ret_dict[k] = list(v)
    return ret_dict

def unionSets(*sets):
    ret_set = set()
    for s in sets:
        ret_set = ret_set.union(s)
    return ret_set

if __name__ == "__main__":
    main()
