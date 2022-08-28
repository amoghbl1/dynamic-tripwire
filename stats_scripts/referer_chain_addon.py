from collections import defaultdict
from mitmproxy import ctx
import json

class RefererChainBuilder:
    def __init__(self):
        self.startup = False
        # Set of domains that belong to the crawl, built up over time and saved
        self.referer_set = set()
        self.browser_request_set = set()

    def load(self, loader):
        # CLI options here
        loader.add_option(
                name     = "initialreferers",
                typespec = str,
                default  = '',
                help     = "Requests in initial referer chain. Separated by a newline.",)
        loader.add_option(
                name     = "results",
                typespec = str,
                default  = '',
                help     = "File to write final stats to.",)

    def startupCheck(self):
        # Weird hack cause lifecycle doesn't load and then trigger a function :/
        if not self.startup:
            self.startup = True
            try:
                with open(ctx.options.initialreferers, "r") as infile:
                    init_referers = json.load(infile)
                    self.referer_set.update(init_referers)
            except json.decoder.JSONDecodeError:
                ctx.log.info("Invalid PII/Domain json file :/")

    def request(self, flow):
        self.startupCheck()
        if flow.request.pretty_url:
            pretty_url = flow.request.pretty_url
        else:
            print("Request without a pretty url? o.O", flow.request)
        # Count urls being hit
        add_to_referers = False
        if 'referer' in flow.request.headers:
            # Referer begins with something we've seen before
            referer = flow.request.headers['referer']
            for my_ref in self.referer_set:
                if referer.startswith(my_ref):
                    add_to_referers = True
        else:
            # No referer, but domian itself begins with something starting from
            # a referer
            for my_ref in self.referer_set:
                if pretty_url.startswith(my_ref):
                    add_to_referers = True
        if add_to_referers:
            self.referer_set.add(pretty_url)
        else:
            self.browser_request_set.add(pretty_url)

    def done(self):
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
        to_write["crawl_requests"] = list(self.referer_set)
        to_write["browser_requests"] = list(self.browser_request_set)
        current_results[pack_hash] = to_write
        with open(ctx.options.results, "w+") as outfile:
            try:
                json.dump(current_results, fp=outfile, sort_keys=True, indent=2)
            except:
                print("Error dumping json to results file :/")
        print("Done writing results", pack_hash, "to", ctx.options.results,
            "crawl requests:", len(self.referer_set),
            "browser requests:", len(self.browser_request_set))

addons = [RefererChainBuilder()]
