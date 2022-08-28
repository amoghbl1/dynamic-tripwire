from mitmproxy import ctx, http
import json
import base64
import os
import zlib
import brotli
import difflib
import hashlib
import datetime
import pickle
import time
import socket

import sys
sys.path.append('./protocs/')
import messages_pb2 as proto

SIGNALING_ADDRESS = ("127.0.0.1", 4590)
FINGERPRINT_TEST = False
FINGERPRINT_REPLACE_JS = "niceDisplayFp.js"
FINGERPRINT_UPLOAD_ENDPOINT = "mobileBrowserUploadRequest"
FINGERPRINT_REPLACE_FILE = "html/niceDisplayFp.js"

PERMISSIONS_UPLOAD_ENDPOINT = "permissionsResultUploadRequest"

class MonitorMobileBrowserTripwire:
    def __init__(self):
        self.tripwires   = {}
        js_file          = open('./mitm/tripwire.js', 'r')
        self.ignoreHashes  = [
                '5535d765b2b211a25f7da6e88bfd961f0740449019fd5c2cfe34e21d86ebe351',
                '3994cd11512365a7bbf6faeb72c6962864d6a139df7a2787ad85d344e683ba25'
                ]
        self.js_tripwire = js_file.read()
        self.intercepted = False
        self.cache = {}

    # TODO: Rewrite this to use better formats instead of pickles.
    # CAUTION: Rewrites whatever self cache we have!
    def loadCache(self):
        if FINGERPRINT_TEST:
            print("Caching disabled, fingerprint test...")
        print("Reading cache from file: " + ctx.options.cache)
        try:
            with open(ctx.options.cache, "rb") as inf:
                self.cache = pickle.load(inf)
        except FileNotFoundError:
            print("Cache file not found! Assuming its a new cache, will write on updates...")

    # CAUTION: Overrites the cache file!
    def saveCache(self):
        if FINGERPRINT_TEST:
            print("Caching disabled, fingerprint test...")
        print("Writing cache " + str(len(self.cache)) + " to file: " + ctx.options.cache)
        try:
            with open(ctx.options.cache, "wb") as ouf:
                pickle.dump(self.cache, ouf, pickle.HIGHEST_PROTOCOL)
        except FileNotFoundError:
            print("Cache directory missing??")

    def load(self, loader):
        loader.add_option(
                name     = "uploadfile",
                typespec = str,
                default  = '',
                help     = "Upload file to write for this test",)
        loader.add_option(
                name     = "runkey",
                typespec = str,
                default  = '',
                help     = "unique id for a run",)
        loader.add_option(
                name     = "cache",
                typespec = str,
                default  = '',
                help     = 'Cache input/output file',)

        # Intercept the flow and send a custom response
    def interceptAndRespond(self, flow, to_send):
        # remove the content length for the response
        if ('content-length' in flow.request.headers):
            del flow.request.headers['content-length']
        resp = http.Response.make(content=to_send.encode())
        flow.response = resp

    def getCacheKey(self, flow):
        url = flow.request.url.split("?")[0]
        port = str(flow.request.port)
        meth = str(flow.request.method)
        # content = str(flow.request.content)
        cache_str = meth + url + port # + content
        return cache_str, cache_str

    def fixHeaders(self, headers):
        # Rewrite old response headers.
        # Lets fix that forbidden date header :P
        del_lst = [b'exipers', b'cache-control']
        if b'Date' in headers:
            headers[b'Date'] = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        for h in del_lst:
            if h in headers:
                del headers[h]
        return headers

    def response(self, flow):
        # Same as request, need to lock this if we're modifying it.
        flow.intercept()
        if FINGERPRINT_TEST:
            # Caching and tripwire injection disabled.
            # Don't need to do anything here for now.
            pass
        else:
            # Do we have it in cache?
            cache_key, cache_str = self.getCacheKey(flow)
            cache_hit = False
            injected, _, _ = self.isInjected(flow)
            if cache_key not in self.cache:
                if not injected:
                    # Lets cache the response!
                    ctx.log.info("Saving to cache: " + cache_str)
                    self.cache[cache_key] = flow.response
                    self.saveCache()
                else:
                    ctx.log.info("Not saving to cache, injection related request!!")
            else:
                # Log cached response for reference.
                ctx.log.info("Cached response: " + str(flow.request.pretty_url))
                cache_hit = True
            # Regardless of cached or not, we need to decide to inject or not
            if flow.response.data.content:
                if ('content-type' in flow.response.headers and 'text/html' in flow.response.headers['content-type']):
                    # Is this the best place to inject our tripwire?
                    html = flow.response.data.content
                    # Deal with the response being compressed.
                    if ('content-encoding' in flow.response.headers):
                        if (flow.response.headers['content-encoding']   == 'gzip'):
                            html = zlib.decompress(html, 16 + zlib.MAX_WBITS)
                        elif (flow.response.headers['content-encoding'] == 'deflate'):
                            html = zlib.decompress(html, -zlib.MAX_WBITS)
                        elif (flow.response.headers['content-encoding'] == 'br'):
                            html = brotli.decompress(html)
                        # It's not compressed on the way out
                        del flow.response.headers['content-encoding']
                    original_HTML = html.decode(errors='ignore') # Breaks without ignoring errors.
                    html        = original_HTML.split('</body>')
                    tripwireTag = '<script id="mitm-tripwire" type="text/javascript" src="' + flow.id + '/index.js"></script>'
                    html[0]     = tripwireTag + html[0]
                    html        = '</body>'.join(html)

                    # Replace content with injected html
                    flow.response.data.content = html.encode()

                    # Encode the html in base 64
                    base64_encoded_html = base64.b64encode(html.encode()).decode()

                    # add it to the dictionary
                    self.tripwires[flow.id] = {
                            'js':            self.js_tripwire % (flow.id),
                            'path':          flow.request.pretty_url,
                            'original_HTML': original_HTML }
                else:
                    print("Non html content, not adding script tag.")
        # Done playing with it now!
        flow.resume()

    def isInjected(self, flow):
        # Path follows domain/flow_id/thing
        split_path = flow.request.data.path.decode().split('/')
        if len(split_path) > 2 and split_path[-2] in self.tripwires:
            # return isInjected?, action, flow_id
            return True, split_path[-1], split_path[-2]
        return False, '', ''

    def signalUploadHit(self, domain, attempt):
        if (attempt > 10): return
        # Need to tell node we got an upload, wait a second first.
        ctx.log.info('Sleeping a second and signaling node.')
        time.sleep(1)
        msg = proto.MITMMessage()
        msg.uploadReceived = True
        msg.domain = domain
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(SIGNALING_ADDRESS)
            send = msg.SerializeToString()
            ctx.log.info("Serialized message:" + str(send))
            sock.send(send)
            sock.close()
        except Exception as e:
            ctx.log.info('Error trying to signal node, retrying: ' + str(e))
            time.sleep(1)
            self.signalUploadHit(domain, attempt + 1)

    def writePayloadToUploadFile(self, flow):
        self.interceptAndRespond(flow, '')
        payload = json.loads(flow.request.data.content.decode())
        # Save the payload uploaded to the output file passed to mitmproxy
        read = {}
        if os.path.isfile(ctx.options.uploadfile):
            with open(ctx.options.uploadfile, 'r') as in_file:
                try:
                    read = json.load(in_file)
                except json.decoder.JSONDecodeError:
                    print("Invalid json found at: " + ctx.options.uploadfile + ", continuing...")
        with open(ctx.options.uploadfile, 'w') as out_file:
            read[flow.request.pretty_url] = payload
            out_file.write(json.dumps(read))


    def request(self, flow):
        # This is where we should load cache, at every single request!
        # There seems to be some problem with loading it once for the whole session.
        # TODO: Find a fix for this.
        self.loadCache()
        # I think it's a good idea to lock the request.
        flow.intercept()
        if flow.request.data:
            # Split handling logic for fingerprint tests vs normal test.
            if FINGERPRINT_TEST:
                # Caching, Tripwires, Upload handling disabled.
                if FINGERPRINT_REPLACE_JS in flow.request.pretty_url:
                    # Serve our own modified script.
                    with open(FINGERPRINT_REPLACE_FILE, 'r') as inf:
                        payload = inf.read()
                        self.interceptAndRespond(flow, payload)
                elif FINGERPRINT_UPLOAD_ENDPOINT in flow.request.pretty_url:
                    # Save uploaded data for analysis.
                    ctx.log.info('Fingerprint uploaded...')
                    self.writePayloadToUploadFile(flow)
                    # We can still use this optimization!
                    self.signalUploadHit(flow.request.pretty_host, 0)
                elif PERMISSIONS_UPLOAD_ENDPOINT in flow.request.pretty_url:
                    # Save uploaded data
                    ctx.log.info('Permissions result uplaoded...')
                    self.writePayloadToUploadFile(flow)
                    self.signalUploadHit(flow.request.pretty_host, 0)
            else:
                # Let's minimally match the request to respond from cache.
                # Pretty URL and port
                cache_key, cache_str = self.getCacheKey(flow)
                if cache_key in self.cache:
                    ctx.log.info("Got a cache hit: " + cache_str)
                    old_response = self.cache[cache_key]
                    # Craft response based on previos response.
                    new_headers = self.fixHeaders(old_response.headers)
                    ctx.log.info("Fixed headers: " + str(new_headers))
                    old_response.headers = new_headers
                    flow.response = old_response
                print('Request URL: ', flow.request.pretty_url)
                injected, action, flowID = self.isInjected(flow)
                if injected:
                    flowStorage = self.tripwires[flowID]
                    if action == 'index.js':
                        ctx.log.info('Index requested!!')
                        self.interceptAndRespond(flow, flowStorage['js'])
                    elif action == 'upload':
                        ctx.log.info('Upload triggered!!')
                        self.writePayloadToUploadFile(flow)
                        # Tell node we got an upload hit, and mention domain where it came from.
                        self.signalUploadHit(flow.request.pretty_host, 0)
        else:
            print("When do flows not have request data??")
        # Done processing the flow now.
        flow.resume()


addons = [
    MonitorMobileBrowserTripwire()
]
