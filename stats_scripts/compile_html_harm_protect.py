#!/usr/bin/env python3
import json
import sys
import re
from collections import defaultdict
from adblockparser import AdblockRules
from multiprocessing import Pool


HTML_HARM_PROTECT = "./combined_stats/html_harm_protect.json"

ALLOWED_HTML_FILE = "./json/allowed_html.json"
EASY_LIST = "./json/easylist.txt"
EASY_PRIVACY = "./json/easyprivacy.txt"

allowed_html = None
easylist_rules = None
easyprivacy_rules = None

# Result keys
BLOCKING_VALID = "Script blocking"
BLOCKING_INVALID = "Unnecessary blocking"
BLOCKING_MISSED = "Blocking missed"

INDIA_DYNAMIC = [
    "static.xx.fbcdn.net",
    "www.facebook.com",
    "static.doubleclick.net/instream/ad_status.js",
    "HasteSupportData",
    "CavalryLogger",
    "static-l3.xnxx-cdn.com",
    "entry_data\":{\"EmbedSimple\":[{}]},\"hostname\":\"www.instagram.com\"",
    "ytcsi.info(",
    "\"link\":\"/quote-of-the-day\"",
    "window.__mirage2 = {petok:",
    "yt.setConfig({'EVENT_ID': \"",
    # links
    "facebook.com/HinduAdhiveshan/",
    "https://www.instagram.com/p/B-YraR2p9E6/",
    "https://www.instagram.com/p/B-cBBfMJH1n/",
    "https://www.instagram.com/p/B_KbdUZJL6V/",
    "https://www.instagram.com/stories/thetrulymadly/",
    "https://www.instagram.com/thetrulymadly/"
]

CHINA_DYNAMIC = [
    "src=\"//tags.tiqcdn.cn/utag/tiqapp/utag.v.js?a=sands-china-limited/hotel/",
    "src=\"https://www.googletagmanager.com/gtag/js",
    "src=\"https://connect.facebook.net/en_US/sdk.js",
    "s.src='https://px.srvcs.tumblr.com/impixu?",
    "Function&&Function.prototype&&Function.prototype.bind&&(/(MSIE ([6789]|10|11))|Trident/",
    "jQuery.extend(Drupal.settings, {\"basePath\":\"\\/\",\"pathPrefix\":\"\",\"ajaxPageState\":{\"theme\":\"clb2016\"",
    "<script crossorigin=\"anonymous\" id=\"__NEXT_DATA__\" type=\"application/json\">\n   {\"props\":{\"initialProps\":{\"statusCode\":0",
    "src=\"../js/jquery.min.js\"",
    "if (/Android|webOS|iPhone|iPod|BlackBerry/i.test(navigator.userAgent))",
    "main_mob.js",
    "doubleclick",
    "sojern.com",
    "match.adsrvr.org",
    # links
    "blog.ipfs.io",
    "chinalawandpolicy.com",
    "t.umblr.com"
]

RUSSIA_DYNAMIC = [
    "tpc.googlesyndication.com",
    "ytcsi.info",
    "pagead2.googlesyndication.com",
    "ca-pub-8076501331922808",
    "googleads.g.doubleclick.net",
    "yt.setConfig({'EVENT_ID':",
    "googMsgType",
    "Function&&Function.prototype&&Function.prototype.bind&&(/(MSIE ([6789]|10|11))|Trident/",
    "uapolitics.com",
    "document.getElementById('cloak",
    "window.__mirage2 = {petok:",
    "googletagservices",
    "static.doubleclick.net",
    "adssettings.google.com/whythisad",
    "qerusgreyt.com/target",
    "nodrugs.ru"
]

ALEXA_DYNAMIC = [
    "us.y.atwola.com",
    "https://mem.gfx.ms/meversion?",
    "s.yimg.com",
    "ytcfg.set({",
    "window.patreon.apiServer = \"www.patreon.com/api",
    "www.gstatic.com/og",
    "src=\"https://web.vortex.data.microsoft.com/collect/",
    "https://oao-js-tag.onemobile.yahoo.com",
    "images-na.ssl-images-amazon.com",
    "src=\"/xjs/_/js/",
    "s.ytimg.com",
    "apis.google.com",
    "window.gwmInstrumentation && window.gwmInstrumentation",
    "https://unagi.amazon.com/1/events/com.amazon.csm.csa.prod",
    "P.now('merch-data-store').execute(function(merchDataStore)",
    "P.when(",
    "P.declare(",
    "src=\"https://s.pinimg.com/ct/core.js\"",
    "src=\"https://sc-static.net/scevent.min.js\"",
    "src=\"https://static.ads-twitter.com/uwt.js\"",
    "src=\"https://assets.video.yahoo.net/",
    "src=\"https://securepubads.g.doubleclick.net/",
    "<script class=\"wafer-state state-added\" type=\"application/json\">",
    "src=\"https://blobs.officehome.msocdn.com/",
    "<script data-a-state='{\"key\":\"rw-dynamic-modal-bootstrap\"}' type=\"a-state\">",
    "<script id=\"Rg-Request-Cache-Config\"",
    "spadeUrl\":\"https://video-edge",
    "moatads.com",
    "Domain=reddit.com",
    "finance.yahoo.com",
    "video.yahoo.com",
    "ads.yahoo.com",
    "xvideos",
    "xv.thumbs.prepareVideo(",
    "microsoft",
    "researchgate.net",
    "#gb-main",
    "google.timers",
    "config.isFreshCustomer",
    "MXMarketplaceRedirectOverlay",
    "yahoo",
    "YAHOO",
    "DefaultSignInCalledBefore",
    "s='/images/nav_logo289_hr.webp'",
    "booking.com",
    "window.booking",
    "window.ytcsi.info",
    "ytcfg.msgs",
    "StackExchange.init",
    "id.google.com/verify",
    "{code:'kn',name:'Kannada'}",
    "s.amazon-adsystem.com/iu3?",
    "if (window.performance) {window.performance.mark && window.performance.mark",
    "fls-na.amazon.com",
    "lgincdnvzeuno.azureedge.net",
    "ADVERTISER_SITE|HOSTED_TOUCHPOINTS|ADVERTISER_APPSTORELINK,TEXT$ADVERTISER_APPSTORELINK|ADVERTISER_SITE|ADVERTISER_APPDEEPLINK",
    "Copyright The Closure Library Authors",
    "player-plasma-ias",
    "cdn.siftscience.com",
    "goalWithValue",
    "BOOKING_HOTEL",
    "concierge_status",
    "b_adults_total",
    "win.vzm",
    "meaningful-paint",
    "this.gbar_=this.gbar_||{};(function(_)",
    "B.require",
    "if (window.requestConfig) { requestConfig.backendTime",
    "googletagmanager",
    "googletagservices",
    "deliveryManager.start()",
    "UA-58591210-1",
    "(!window.canAskForCookieConsent || !window.canAskForCookieConsent())",
    "redditstatic",
    "google-analytics",
    "AntpUserCacheId",
    "c5.rgstatic.net",
    "cf.bstatic.com",
    "cdn.sstatic.net",
    "adtechus",
    "requestConfig.backendTime = ",
    "src=\"/yts/jsbin/",
    "!window.useQuantcast && window.loadDeferredObjects && window.loadDeferredObjects();",
    "if (window.ue",
    "var ue_t0=ue_t0||+new Date();",
    "try{JAC.sandbox.unload()}catch(e){}",
    "amazon",
    "app.link",
    "src=\"../js/sfext-min.js\"",
    "function getPerformanceObjectData(object)",
    "root.App || (root.App = {});",
    # Links
    "rpc-php.trafficfactory.biz/click",
    "https://ad.doubleclick.net/ddm/trackclk/",
    "https://alb.reddit.com/",
    "https://accounts.google.com/ServiceLogin",
    "https://forms.donaldjtrump.com/landing/china-joe",
    "https://www.google.com/webhp?",
    "i.redd.it",
    "v.redd.it",
    "products.office.com",
    "support.google.com",
    "https://www.verizonmedia.com/policies/"
]

HONEYPAGE_DYNAMIC = [
    "window._mNDetails.loadTag(\"623537980\"", # Sometimes script rewrite is not complete
    "src=\"https://connect.facebook.net/en_US/sdk.js", # Facebok plugin might rewrite itself
    "nonce=\"8GF7p8ES\"", # Google/Facebook tracking nonce is constant, other parts might change
    "ca-pub-6448106054380521", # Google ad plugin, rendered differently
    "n.p=\"https://platform.twitter.com/\"",
    "https://platform.twitter.com/js/button",
    "Function&&Function.prototype&&Function.prototype.bind&&(/(MSIE"
]



def main():
    # We need some paths to compute this.
    OUT_DIR = "./combined_stats/"
    REQUESTS_FILE = "/crawlRequests.json"
    HTML_DIFF_FILE = "/htmlDiffStats.json"
    if len(sys.argv) < 2:
        print("Please provide at least 1 path to process htmlDiffStats file from.")
        return
    all_stats = {}
    ctr = 0
    for i in sys.argv[1:]:
        ctr += 1
        with open(i + HTML_DIFF_FILE, "r") as inf:
            this_diff = json.load(inf)
            for k, v in this_diff.items():
                all_stats[k + str(ctr)] = v
    setup_globals()
    global easylist_rules
    global easyprivacy_rules
    blocking_scores = {}
    with Pool() as p:
        results = p.map(process_all_stats_piece, all_stats.items())
    # Reduce results
    blocking_scores = {}
    for pack_hash, scores_dict in results:
        blocking_scores[pack_hash] = scores_dict

    blocking_valid = get_blocking_packs(BLOCKING_VALID, blocking_scores)
    blocking_invalid = get_blocking_packs(BLOCKING_INVALID, blocking_scores)
    blocking_allowed = get_blocking_packs(BLOCKING_MISSED, blocking_scores)
    blocking_overall = {}
    blocking_overall[BLOCKING_VALID] = blocking_valid
    blocking_overall[BLOCKING_INVALID] = blocking_invalid
    blocking_overall[BLOCKING_MISSED] = blocking_allowed

    print("Easylist blockers:", len(blocking_valid))
    print("Non-easylist blockers:", len(blocking_invalid))
    print("Easylist but allowed:", len(blocking_allowed))

    # harm_protect_result = reduce_dict_dict_int(harm_protect_result)
    with open(HTML_HARM_PROTECT, "w") as ouf:
        json.dump(
            reduce_blocking_score_dict_to_scores(blocking_scores,
                blocking_overall),
            sort_keys=True,
            indent=2,
            fp=ouf
        )

def process_all_stats_piece(pack_hash_stat):
    pack_hash_ctr, html_stat = pack_hash_stat
    result_dict = defaultdict(set)
    print("Processing", pack_hash_ctr)
    pack_hash = pack_hash_ctr.split("-")
    pack_hash = "-".join(pack_hash[:2])
    pack_hash = ".".join(pack_hash.split(".")[:-1])
    easylist_hit = set()
    easylist_miss = set()
    easyprivacy_hit = set()
    easyprivacy_miss = set()
    for domain, stat in html_stat.items():
        # Cleaning stat, removing all manually flagged content
        stat = clean_stat(domain, stat)
        if "missing_scripts" in stat:
            missing_scripts = stat["missing_scripts"]
            extra_scripts = []
            overlap_scripts = []
            if "extra_scripts" in stat:
                extra_scripts = stat["extra_scripts"]
            if "overlap_scripts" in stat:
                overlap_scripts = stat["overlap_scripts"]
            # At this point, we have everything to remove dynamic content
            extra_scripts_updated, missing_scripts_updated = \
                account_for_dynamism(extra_scripts, missing_scripts, \
                overlap_scripts)
            # OK, this difference is now the scripts that are missing/extra
            stat["missing_scripts"] = missing_scripts_updated
            stat["extra_scripts"] = extra_scripts_updated
            # Crosscheck blocked scripts with easylist and easyprivacy list
            missing_script_sources = get_srcs_from_scripts(missing_scripts_updated)
            hit, miss = get_rules_hit_miss(easylist_rules, missing_script_sources)
            easylist_hit = easylist_hit.union(hit)
            easylist_miss = easyprivacy_miss.union(miss)
            hit, miss = get_rules_hit_miss(easyprivacy_rules, missing_script_sources)
            easyprivacy_hit = easyprivacy_hit.union(hit)
            easyprivacy_miss = easyprivacy_miss.union(miss)

        if "missing_links" in stat:
            missing_links = stat["missing_links"]
            extra_links = []
            overlap_links = []
            if "extra_links" in stat:
                extra_links = stat["extra_links"]
            if "overlap_links" in stat:
                overlap_links = stat["overlap_links"]
            extra_links_updated, missing_links_updated = \
                account_for_dynamism(extra_links, missing_links, \
                overlap_links)
            # Write these updated missing and extra links to the stat
            stat["extra_links"] = extra_links_updated
            stat["missing_links"] = missing_links_updated
            hit, miss = get_rules_hit_miss(easylist_rules, missing_links_updated)
            easylist_hit = easylist_hit.union(hit)
            easylist_miss = easylist_miss.union(miss)
            hit, miss = get_rules_hit_miss(easyprivacy_rules, missing_links_updated)
            easyprivacy_hit = easyprivacy_hit.union(hit)
            easyprivacy_miss = easyprivacy_miss.union(miss)
        # Process easylist overlaps
        if len(easylist_hit) > 0 or len(easyprivacy_hit) > 0:
            result_dict[BLOCKING_VALID] = \
                result_dict[BLOCKING_VALID].union(
                    easylist_hit.union(easyprivacy_hit)
                )
        if len(easylist_miss) > 0 or len(easylist_miss) > 0:
            result_dict[BLOCKING_INVALID] = \
                result_dict[BLOCKING_INVALID].union(
                    easylist_miss.union(easyprivacy_miss)
                )
    return (pack_hash, result_dict)

def setup_globals():
    global allowed_html
    global easylist_rules
    global easyprivacy_rules
    with open(ALLOWED_HTML_FILE, "r") as inf:
        allowed_html = json.load(inf)
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

def get_blocking_packs(blocking_type, blocking_scores):
    valid_blockers = set()
    for pack_hash, blocking_found in blocking_scores.items():
        if blocking_type in blocking_found and \
            len(blocking_found[blocking_type]) > 0:
                valid_blockers.add(pack_hash)
    return valid_blockers

def get_rules_hit_miss(rules, entries):
    hit = set()
    miss = set()
    for entry in entries:
        if entry and rules.should_block(entry):
            hit.add(entry)
        else:
            miss.add(entry)
    return hit, miss

def get_srcs_from_scripts(scripts):
    sources = set()
    regex = re.compile("src=\".*\"")
    for script in scripts:
        for source in regex.findall(script):
            sources.add(source)
    return list(sources)

def reduce_blocking_score_dict_to_scores(blocking_scores, blocking_overall):
    ret_dict = defaultdict(lambda: defaultdict(int))
    blocking_max = defaultdict(int)
    for pack_hash, blocking_score_dict in blocking_scores.items():
        for blocking_feature, blocked_content in blocking_score_dict.items():
            if blocking_max[blocking_feature] < len(blocked_content):
                blocking_max[blocking_feature] = len(blocked_content)
    for pack_hash, blocking_score_dict in blocking_scores.items():
        for blocking_feature, blocked_content in blocking_score_dict.items():
            if blocking_feature == BLOCKING_VALID:
                ret_dict[pack_hash][blocking_feature] = \
                    len(blocked_content) / blocking_max[blocking_feature]
            else:
                print("Invalid blocking score feature found:", blocking_feature)
    return ret_dict

def clean_stat(domain, stat):
    ret_stat = {}
    allowed_links = allowed_html["links"]
    allowed_scripts = allowed_html["scripts"]
    allowed_tags = allowed_html["tags"]
    # Construct cleaning lists for links and clean extra and missing
    start_list, in_list, is_list = new_allowed_lists(allowed_html["links"])
    if domain in allowed_links:
        start_list, in_list, is_list = ignore_add(allowed_links[domain], start_list, in_list, is_list)
    for l in ["extra_links", "missing_links"]:
        if l in stat:
            ret_stat[l] = clean_stat_piece(stat[l], start_list, in_list, is_list)
    # Construct cleaning lists for scripts and clean extra and missing
    start_list, in_list, is_list = new_allowed_lists(allowed_html["scripts"])
    if domain in allowed_scripts:
        start_list, in_list, is_list = ignore_add(allowed_scripts[domain], start_list, in_list, is_list)
    for s in ["extra_scripts", "missing_scripts"]:
        if s in stat:
            ret_stat[s] = clean_stat_piece(stat[s], start_list, in_list, is_list)
    # Construct cleaning lists for tags and clean extra and missing
    start_list, in_list, is_list = new_allowed_lists(allowed_html["tags"])
    if domain in allowed_tags:
        start_list, in_list, is_list = ignore_add(allowed_tags[domain], start_list, in_list, is_list)
    for t in ["extra_tags", "missing_tags"]:
        if t in stat:
            ret_stat[t] = clean_stat_piece(stat[t], start_list, in_list, is_list)
    # Add in all_links and all_scripts
    for s in ["all_links", "all_scripts"]:
        if s in stat:
            ret_stat[s] = stat[s]
    return ret_stat

def new_allowed_lists(original_list):
    return original_list["ALL_START"][:], original_list["ALL_IN"][:], original_list["ALL_IS"][:]

def ignore_add(element, starts, ins, iss):
    try:
        starts += element["starts"]
    except KeyError:
        pass
    try:
        ins += element["ins"]
    except KeyError:
        pass
    try:
        iss += element["iss"]
    except KeyError:
        pass
    return starts, ins, iss

def clean_stat_piece(to_clean, start_list, in_list, is_list):
    cleaned = []
    for i in to_clean:
        add_flag = True
        if i == None:
            add_flag = False
        else:
            for j in start_list:
                if i.startswith(j):
                    add_flag = False
                    break
        if add_flag:
            cleaned.append(i)
    to_clean = cleaned
    cleaned = []
    for i in to_clean:
        add_flag = True
        for j in in_list:
            if j in i:
                add_flag = False
                break
        if add_flag:
            cleaned.append(i)
    to_clean = cleaned
    cleaned = []
    for i in to_clean:
        add_flag = True
        for j in is_list:
            if i == j:
                add_flag = False
                break
        if add_flag:
            cleaned.append(i)
    return cleaned

def account_for_dynamism(extra, missing, overlap):
    if None in extra:
        extra.remove(None)
    if None in missing:
        missing.remove(None)
    if None in overlap:
        overlap.remove(None)
    ret_e = []
    ret_m = []
    dynamic = set(
        # INDIA_DYNAMIC +
        # CHINA_DYNAMIC +
        # RUSSIA_DYNAMIC +
        ALEXA_DYNAMIC +
        HONEYPAGE_DYNAMIC
    )
    extra = set(extra)
    missing = set(missing)
    overlap = set(overlap)
    for e in extra:
        add_flag = True
        for d in dynamic:
            # If this piece is possibly dynamically generated
            if d in e:
                for m in missing.union(overlap):
                    # If this piece is also missing
                    if d in m:
                        add_flag = False
                        break
        if add_flag:
            ret_e.append(e)
    for m in missing:
        add_flag = True
        for d in dynamic:
            if d in m:
                for e in extra.union(overlap):
                    if d in e:
                        add_flag = False
                        break
        if add_flag:
            ret_m.append(m)
    return ret_e, ret_m

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
