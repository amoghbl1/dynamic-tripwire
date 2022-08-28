'use strict';

(() => {
    class WebTripwire {
        constructor(flowID) {
            this.uploadURL = `${flowID}/upload`
            window.addEventListener('load', this.uploadData.bind(this));
        }

        /**
         * Builds the doctype of the current page
         */
        getPageHTML() {
            if(document.doctype) {
                const base     = `<!DOCTYPE ${ document.doctype.name }`;
                const publicId = document.doctype.publicId
                    ? ` PUBLIC "${ document.doctype.publicId }"`
                    : '';
                const systemId = document.doctype.systemId
                    ? ` "${ document.doctype.systemId }"`
                    : '';
                return `${base}${publicId}${systemId}>${document.documentElement.outerHTML}`;
            } else {
                return `${document.documentElement.outerHTML}`;
            }
        };

        async uploadData(){
            // alert("Upload called!");
            // Delete this script before we upload the html.
            const tripwire = document.getElementById('mitm-tripwire');
            tripwire.parentElement.removeChild(tripwire);
            var payload = {
                loadedHTML: this.getPageHTML()
            };
            await this.sendTrigger(payload, this.uploadURL);
            // Upload a bunch of data now!
        }

        sendTrigger( payload, url ) {
            const request = new XMLHttpRequest();
            request.open( 'POST', url, true );
            return request.send( JSON.stringify( payload ) );
        }
    }

    const tripwire = new WebTripwire('%s');
})();
