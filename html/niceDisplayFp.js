document.addEventListener('DOMContentLoaded', function() {
    (async() => {
        const fingerprint = await fpCollect.generateFingerprint();

        const rowsFingerprint = [];
        rowsFingerprint.push('<tr><th>Attribute</th><th class="breakword">Value</th><tr/>');
        Object.keys(fingerprint).forEach(function(key) {
            if (key === 'canvas') {
                rowsFingerprint.push('<tr><td>'+ key + '</td><td class="breakword"><img src="' + fingerprint[key].image + '"></td><tr/>');
            } else{
                rowsFingerprint.push('<tr><td>'+ key + '</td><td class="breakword">' + JSON.stringify(fingerprint[key]) + '</td><tr/>');
            }
        });

         document.getElementById('fp').innerHTML = rowsFingerprint.join('');

        const xhr = new XMLHttpRequest();

        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4 && xhr.status === 200){
                const scannerResults = JSON.parse(xhr.responseText);
                const INCONSISTENT = 1;
                const UNSURE = 2;
                const CONSISTENT = 3;

                const resultToLabel = new Map([
                    [INCONSISTENT, 'Inconsistent'],
                    [UNSURE, 'Unsure'],
                    [CONSISTENT, 'Consistent']
                ]);

                const rowsScanner = [];
                rowsScanner.push('<tr><th>Test</th><th class="breakword">Result</th><th>Data</th><tr/>');

                Object.keys(scannerResults).forEach(function(key) {
                    let resultTest = scannerResults[key];
                    let color = 'green';
                    if (resultTest.consistent === INCONSISTENT)
                        color = 'red';

                    rowsScanner.push('<tr><td style="color:'+color+';">'+ key + '</td><td class="breakword" style="color:'+color+'">' + resultToLabel.get(resultTest.consistent) + '</td><td style="color:'+color+';">'+ JSON.stringify(resultTest.data)+'</td><tr/>');

                });
                document.getElementById('scanner').innerHTML = rowsScanner.join('');

                // Custom mobile browser part, lets upload data to mitmproxy.
                const request = new XMLHttpRequest();
                request.open('POST', '/mobileBrowserUploadRequest', true);
                const payload = {
                    fingerprint: fingerprint,
                    testResults: scannerResults
                };
                request.send(JSON.stringify(payload));
            }
        };

        xhr.open('POST', '/bots/collectfp');
        xhr.setRequestHeader('Content-Type', 'application/json');
        // Don't worry this uuid is not for tracking. A new one is generated at each request. It is to link HTTP headers
        // and a fingerprint
        fingerprint.uuid = uuid;
        fingerprint.url = window.location.href;
        xhr.send(JSON.stringify(fingerprint));



    })();

});
