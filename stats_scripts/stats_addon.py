from collections import defaultdict
from mitmproxy import ctx
import pickle
import sys
import json
import re
import hashlib
import os

class DumpFilter:
    def __init__(self):
        self.urls = defaultdict(int)
        self.request_info = {}
        self.startup = False
        self.pii = None
        self.hist = None
        self.piihit = False
        self.histhit = False
        self.piilog = defaultdict(set)
        self.histlog = defaultdict(lambda: defaultdict(list))
        self.baseline_set = set()
        self.overlap_with_baseline = None
        self.missing_requests = None
        self.new_requests = {}
        self.new_requests_size = 0
        self.DEBUG_TEXT = False

    def load(self, loader):
        loader.add_option(
                name     = "baseline",
                typespec = str,
                default  = '',
                help     = "Upload file to write for this test",)
        loader.add_option(
                name     = "baselinedir",
                typespec = str,
                default  = '',
                help     = "Directory where multiple baselines are",)
        loader.add_option(
                name     = "write",
                typespec = bool,
                default  = False,
                help     = "Do we need to write the baseline file...",)
        loader.add_option(
                name     = "pii",
                typespec = str,
                default  = '',
                help     = "PII to grep text and request body for. Separated by a newline.",)
        loader.add_option(
                name     = "domains",
                typespec = str,
                default  = '',
                help     = "Domains to look for, for history uploaders. Separated by a newline.",)
        loader.add_option(
                name     = "results",
                typespec = str,
                default  = '',
                help     = "File to write final stats to.",)

    def startupCheck(self):
        # Weird hack cause lifecycle doesn't load and then trigger a function :/
        if not self.startup:
            self.startup = True
            # Only load this if we're not writing
            if not ctx.options.write:
                # Load multiple baseline pickles and combine
                baseline_dir = "/".join(ctx.options.baseline.split("/")[:-1])
                baseline_postfix = ctx.options.baseline.split("/")[-1]
                for baseline in os.listdir(baseline_dir):
                    if baseline.endswith( baseline_postfix + ".pickle"):
                        with open(baseline_dir + "/" + baseline, "rb") as infile:
                            this_baseline = pickle.load(infile)
                            # Process the baseline ds's right here.
                            self.baseline_set = self.baseline_set.union(set(map(self.getUrl, this_baseline["url_dict"].keys())))
                try:
                    with open(ctx.options.pii, "r") as infile:
                        self.pii = json.load(infile)
                    with open(ctx.options.domains, "r") as infile:
                        self.hist = json.load(infile)
                except FileNotFoundError:
                    ctx.log.info("Invalid PII file supplied :/")
                except json.decoder.JSONDecodeError:
                    ctx.log.info("Invalid PII/Domain json file :/")

    def request(self, flow):
        self.startupCheck()
        # Count urls being hit
        pretty_url = str(flow.request.pretty_url)
        request_text = str(flow.request.text)
        self.urls[pretty_url] += 1
        current_domain = self.getUrl(pretty_url)
        # We only do the check for pii if we're not writing baseline.
        if ctx.options.write:
            return
        # We only need to pii/hist check if it's a non standard request.
        # Assuming our baseline is well curated to only contact legit domains.
        try:
            for pik in self.pii.keys():
                # Try to decode the content
                result, extras = self.advanceSearch(pik, flow)
                if result:
                    self.piihit = True
                    self.piilog[pik].add(current_domain)
            for h in self.hist:
                result, extras = self.advanceSearch(h, flow)
                if result:
                    self.histhit = True
                    for extra in extras:
                        # Log not only domain, but also flow for further analysis
                        if h == current_domain:
                            continue
                        to_log = pretty_url + " MOBRODEMARCATOR " + request_text
                        if extra != "":
                            self.histlog[h + "_" + extra][current_domain].append(to_log)
                        else:
                            self.histlog[h][current_domain].append(to_log)
            self.request_info[pretty_url] = request_text
        except ValueError as e:
            ctx.log.info("Value error fetching request text.")

    def done(self):
        if ctx.options.write:
            try:
                with open(ctx.options.baseline, "wb") as outfile:
                    print("Dumping to baseline file:" + str(ctx.options.baseline))
                    tmp = {} # Figure the stuff you want to process, to compare to the baseline.
                    tmp["url_dict"] = self.urls # Just url dicts at the moment.
                    pickle.dump(tmp, outfile, pickle.HIGHEST_PROTOCOL)
            except FileNotFoundError:
                ctx.log.info("Invalid baseline directory/files?")
        else:
            # Compare to baseline, just do host set diff for now.
            local_set = set(map(self.getUrl, self.urls.keys()))
            url_diff = local_set - self.baseline_set
            all_possibilities = set()
            for u in url_diff:
                for d in self.urls.keys():
                    if u in d:
                        all_possibilities.add(d)
            print("Processing done for nonbaseline", len(all_possibilities))
            for u in all_possibilities:
                self.new_requests[u] = self.urls[u] # Count number of requests to each new url
                self.new_requests_size += len(self.request_info[u]) # Count total amount of data sent
            print("All non baseline urls: ", len(url_diff), ", Total size: ", self.new_requests_size)
            overlap = len(local_set - url_diff)
            self.overlap_with_baseline = list(self.baseline_set.intersection(local_set))
            self.missing_requests = list(self.baseline_set - local_set)
            print("Overlap: ", overlap)
            print("PII Log:", len(self.piilog))
            print("History Log:", len(self.histlog))
            self.writeResults()

    def advanceSearch(self, string, flow):
        # Does a bunch of things to string and searches for it in the flow.
        found = False
        retlst = []
        smd5 = hashlib.md5(string.encode()).hexdigest()
        ss1 = hashlib.sha1(string.encode()).hexdigest()
        ss224 = hashlib.sha224(string.encode()).hexdigest()
        ss256 = hashlib.sha256(string.encode()).hexdigest()
        if self.DEBUG_TEXT:
            ctx.log.info(flow.request.text)
        text = str(flow.request.text)
        pretty_url = str(flow.request.pretty_url)
        if (re.search(string, text, re.IGNORECASE) or re.search(string, pretty_url, re.IGNORECASE)):
            found = True
            retlst.append("")
        elif (re.search(smd5, text, re.IGNORECASE) or re.search(smd5, pretty_url, re.IGNORECASE)):
            found = True
            retlst.append("") # Ignore extra info for now
        elif (re.search(ss1, text, re.IGNORECASE) or re.search(ss1, pretty_url, re.IGNORECASE)):
            found = True
            retlst.append("")
        elif (re.search(ss224, text, re.IGNORECASE) or re.search(ss224, pretty_url, re.IGNORECASE)):
            found = True
            retlst.append("") # Ignore extra info for now
        elif (re.search(ss256, text, re.IGNORECASE) or re.search(ss256, pretty_url, re.IGNORECASE)):
            found = True
            retlst.append("") # Ignore extra info for now
        if ":" in string or "-" in string:
            string = string.replace(":", "")
            string = string.replace("-", "")
            res1, res2 = self.advanceSearch(string, flow)
            retlst.extend(res2)
            return (found | res1), retlst
        return found, retlst

    def getUrl(self, s):
        splits = s.split("/")
        if len(splits) > 2:
            return splits[2]
        return s

    def writeResults(self):
        # Write all stats we collect.
        pack_hash = ctx.options.rfile.split("/")[-1][:-5]
        current_results = {}
        try:
            with open(ctx.options.results, "r") as infile:
                current_results = json.load(infile)
        except json.decoder.JSONDecodeError:
            print("Invalid json found at: " + ctx.options.uploadfile + ", continuing...")
        except FileNotFoundError:
            print("File", ctx.options.results, "not found, will create it and write...")
        if pack_hash in current_results:
            print("Result already exists!! Will be overwritten...")
        to_write = {}
        to_write["overlap"] = list(self.overlap_with_baseline)
        to_write["new_requests"] = self.new_requests
        to_write["new_requests_size"] = self.new_requests_size
        to_write["missing_request_domains"] = self.missing_requests
        to_write["pii_log"] = {k: list(v) for k, v in self.piilog.items()}
        to_write["history_log"] = self.histlog
        to_write["domains"] = len(self.hist)
        to_write["all_requests"] = list(self.urls.keys())
        current_results[pack_hash] = to_write
        with open(ctx.options.results, "w+") as outfile:
            try:
                json.dump(current_results, fp=outfile, sort_keys=True, indent=2)
            except:
                print("Error dumping json to results file :/")
        print("Done writing results", pack_hash, "to", ctx.options.results)

addons = [DumpFilter()]
