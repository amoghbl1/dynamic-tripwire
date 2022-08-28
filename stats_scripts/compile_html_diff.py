#!/usr/bin/env python3
import json
import sys
import re
from collections import defaultdict
from adblockparser import AdblockRules

ALLOWED_HTML_FILE = "./json/allowed_html.json"
HTML_DIFF_SUMMARY = "./combined_stats/html_diff_summary.json"

allowed_html = None

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
    "c1.patreon.com"
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
    "youtube.com"
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

HONEYPGE_TWITTER_LINKS = [
    "https://twitter.com/TwitterDev",
    "https://twitter.com/intent/tweet?screen_name=TwitterDev&ref_src=twsrc%5Etfw",
    "https://twitter.com/intent/tweet?text=Hello%20world",
]

HONEYPAGE_TWITTER_REWRITE = [
    "https://twitter.com/intent/tweet?original_referer=http%3A%2F%2F10.42.0.1%2Fhoney.html&ref_src=twsrc%5Etfw&screen_name=TwitterDev&tw_p=tweetbutton",
    "https://twitter.com/intent/tweet?original_referer=http%3A%2F%2F10.42.0.1%2Fhoney.html&ref_src=twsrc%5Etfw&text=Hello%20world&tw_p=tweetbutton&url=http%3A%2F%2F10.42.0.1%2Fhoney.html"
]

HONEYPAGE_TWITTER_SCRIPT_PIECES = [
    "n.p=\"https://platform.twitter.com/\"",
    "src=\"https://platform.twitter.com/js/button",
    "src=\"https://cdn.syndication.twimg.com/widgets/followbutton/info.json?callback=__twttr.setFollowersCountAndFollowing&amp;lang=en&amp;screen_names=TwitterDev"
]

HONEYPAGE_AMAZON_LINK = "https://www.amazon.com/gp/product/0062834843/ref=as_li_qf_asin_il_tl?ie=UTF8&tag=wwwdanielsilv-20&creative=9325&linkCode=as2&creativeASIN=0062834843&linkId=a833b2f0e88349151b0ca3dda08938bf"

MANUAL_IGNORE_DOMAIN = [
    "www.teach.org",
    "www.theatlantic.com",
    "www.businessinsider.com",
    "www.nydailynews.com",
    "www.cnn.com",
    "portal.ct.gov",
    "forms.donaldjtrump.com",
]

def main():
    # We need some paths to compute this.
    OUT_DIR = "./combined_stats/"
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
    mis_script_set = defaultdict(lambda: defaultdict(set))
    ext_script_set = defaultdict(lambda: defaultdict(set))
    mis_link_set = defaultdict(lambda: defaultdict(set))
    ext_link_set = defaultdict(lambda: defaultdict(set))
    twitter_block = set()
    script_adder = set()
    link_adder = set()
    link_remover = set()
    fb_block = set()
    goog_ad_block = set()
    extra_tags = defaultdict(set)
    missing_tags = defaultdict(set)
    miss_all = set()
    for pack_hash_ctr, v in all_stats.items():
        print("Processing", pack_hash_ctr)
        pack_hash = pack_hash_ctr.split("-")
        pack_hash = "-".join(pack_hash[:2])
        pack_hash = ".".join(pack_hash.split(".")[:-1])
        honeypage_twitter_script_missing = False
        honeypage_twitter_link_rewrite = False
        for domain, stat in v.items():
            # Cleaning stat, removing all manually flagged content
            stat = clean_stat(domain, stat)
            if "extra_tags" in stat:
                extra_tags[domain].update(stat["extra_tags"])
            if "missing_tags" in stat:
                missing_tags[domain].update(stat["missing_tags"])
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
                extra_scripts_updated, missing_scripts_updated = \
                    drop_manual_domains(extra_scripts_updated, missing_scripts_updated)
                # OK, this difference is now the scripts that are missing/extra
                stat["missing_scripts"] = missing_scripts_updated
                stat["extra_scripts"] = extra_scripts_updated

                # Get missing script overall stats
                for missing_script in missing_scripts_updated:
                    miss_all.add(pack_hash)
                    mis_script_set[missing_script][pack_hash].add(domain)
                    # Nonce is part of the facebook plugin but for some reason, leads to google ad requests that all maintain it
                    # So if this is missing, it means the facebook script went through and loaded, but the following google script
                    # was blocked
                    if "nonce=\"8GF7p8ES\"" in missing_script:
                        goog_ad_block.add(pack_hash)
                    if "src=\"https://connect.facebook.net/en_US/sdk.js?" in missing_script:
                        fb_block.add(pack_hash)
                    for piece in HONEYPAGE_TWITTER_SCRIPT_PIECES:
                        if piece in missing_script:
                            honeypage_twitter_script_missing = True
                # Get extra script overall stats
                for extra_script in extra_scripts_updated:
                    ext_script_set[extra_script][pack_hash].add(domain)
                if len(extra_scripts_updated) > 0:
                    script_adder.add(pack_hash)
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
                extra_links_updated, missing_links_updated = \
                    drop_manual_domains(extra_links_updated, missing_links_updated)
                # Write these updated missing and extra links to the stat
                stat["extra_links"] = extra_links_updated
                stat["missing_links"] = missing_links_updated

                # Get missing links overall stat
                for missing_link in missing_links_updated:
                    miss_all.add(pack_hash)
                    mis_link_set[missing_link][pack_hash].add(domain)

                # Get extra link overall stat
                for extra_link in extra_links_updated:
                    ext_link_set[extra_link][pack_hash].add(domain)
                    if extra_link in HONEYPAGE_TWITTER_REWRITE:
                        honeypage_twitter_link_rewrite = True

        # More complex check which accounts for a combination of missing links and missing scripts
        if honeypage_twitter_script_missing and not honeypage_twitter_link_rewrite:
            twitter_block.add(pack_hash)

    print("Missing Scripts:", len(mis_script_set))
    print("Extra Scripts:", len(ext_script_set))
    print("Missing Links:", len(mis_link_set))
    print("Extra Links:", len(ext_link_set))
    print("Facebook block:", len(fb_block))
    print("Twitter block:", len(twitter_block))
    print("Google ad block:", len(goog_ad_block))
    print("Missing all:", len(miss_all))


    blockers = unionSets(fb_block, twitter_block, goog_ad_block)
    print("Blockers:", len(blockers))
    adders = script_adder.union(link_adder)
    print("link_adder:", len(link_adder), "link_remover:", len(link_remover))
    print("Adder:", len(adders))
    modifiers = blockers.union(adders)
    print("Modifiers:", len(modifiers))
    tmp = {}
    for k, v in missing_tags.items():
        tmp[k] = list(v)
    missing_tags = tmp
    tmp = {}
    for k, v in extra_tags.items():
        tmp[k] = list(v)
    extra_tags = tmp
    with open("extra_links.json", "w") as el, \
            open("extra_scripts.json", "w") as es,\
            open("missing_links.json", "w") as ml, \
            open("missing_scripts.json", "w") as ms:
        json.dump({"extra_links": reduceDictDictSet(ext_link_set)},
            sort_keys=True, indent=2, fp=el)
        json.dump({"missing_links": make_keys_TLDs(mis_link_set)},
            sort_keys=True, indent=2, fp=ml)
        json.dump({"extra_scripts": reduceDictDictSet(ext_script_set)},
            sort_keys=True, indent=2, fp=es)
        json.dump({"missing_scripts": make_keys_TLDs(mis_script_set, True)},
            sort_keys=True, indent=2, fp=ms)

def setup_globals():
    global allowed_html
    with open(ALLOWED_HTML_FILE, "r") as inf:
        allowed_html = json.load(inf)

def get_srcs_from_scripts(scripts):
    sources = set()
    regex = re.compile("src=\".*\"")
    for script in scripts:
        for source in regex.findall(script):
            sources.add(source)
    return list(sources)


def make_keys_TLDs(dict_dict_set, scripts=False):
    ret_dict = {}
    for k, v in dict_dict_set.items():
        if scripts:
            srcs = get_srcs_from_scripts([k])
            if len(srcs) > 1:
                print(srcs)
                print("Multiple sources on a single script o.O")
            if len(srcs) != 0:
                k = srcs[0]
        # Get TLD
        try:
            k = k.split(":")[1].split('/')[2]
        except IndexError:
            pass
        if k in ret_dict:
            vals = set(ret_dict[k])
            vals.update(v)
            ret_dict[k] = list(vals)
        else:
            ret_dict[k] = list(v)
    for tld, browsers in ret_dict.items():
        if len(browsers) > 50:
            print("Heavy domain:", tld)
    return ret_dict

def drop_manual_domains(stat1, stat2):
    stat1_new = set()
    stat2_new = set()
    for s in stat1:
        drop = False
        for domain in MANUAL_IGNORE_DOMAIN:
            if domain in s:
                drop = True
        if not drop:
            stat1_new.add(s)
    for s in stat2:
        drop = False
        for domain in MANUAL_IGNORE_DOMAIN:
            if domain in s:
                drop = True
        if not drop:
            stat2_new.add(s)
    return stat1_new, stat2_new

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

def reduceToPacks(pack_hashs):
    packs = set()
    for pack_hash in pack_hashs:
        packs.add(pack_hash.split("-")[0])
    return packs

def wordpress(script):
    if "wpl-likebox" in script:
        return True
    if "postmessage.js" in script:
        return True
    return False

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

def unionSets(*sets):
    ret_set = set()
    for s in sets:
        ret_set = ret_set.union(s)
    return ret_set

if __name__ == "__main__":
    main()
