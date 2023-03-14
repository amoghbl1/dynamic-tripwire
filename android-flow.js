'use strict';

// Types of tests flags
const DEBUG = true;
const MANUAL_TEST = false;
const FINGERPRINT_TEST = false;
const INDIA_LIST = false;
const RUSSIA_LIST = false;
const CHINA_LIST = false;
const PASS_FAIL = false;
const ALEXA_TOP = false;


// Logging related variables
const DATE = new Date();
const RESULTS_BASE_DIR = `./crawl_results`;
const RESULTS_DIR = `${RESULTS_BASE_DIR}/${DATE.toISOString().split('T')[0].replace(/-/g, "") + DATE.toTimeString().split(' ')[0].replace(/:/g, "")}`;
const CACHE_FILE = `${RESULTS_DIR}/cache_file`; // Where we save the cache
const LOGS_DIR = `${RESULTS_DIR}/logs/`;
const SCREENSHOTS_DIR = `${RESULTS_DIR}/screenshots/`;
const BASELINE_DIR = `${LOGS_DIR}/baseline/`;
const BASELINE_CACHE = `${BASELINE_DIR}/cache_file`;
const BASELINE_SCREENSHOTS_DIR = `${BASELINE_DIR}/screenshots/`;

// Helper related variables
var APKS_JSON = 'apk_lists/apks.json';
if (INDIA_LIST) {
    APKS_JSON = 'apk_lists/india_apks.json';
} else if (RUSSIA_LIST) {
    APKS_JSON = 'apk_lists/russia_apks.json';
} else if (CHINA_LIST) {
    APKS_JSON = 'apk_lists/china_apks.json';
}

const MITM_CTRL = `./mitm/mitmproxy-ctrl`;
const SIGNALING_PORT = 4590;
const FSMON = "/data/local/tmp/fsmon";
const FSMON_LOG = "/data/local/tmp/runlog";
const BASELINE_PACKAGE_NAME = 'com.homezoneproject.mywebviewapp';

// Modules
const sleep = ms => new Promise( resolve => setTimeout( resolve, ms ) );
const fs = require('fs');
const exec = require('child_process').exec;
const proto = require('./protocs/messages_pb')
const net = require('net');
const readline = require('readline');
const util = require('util');
const pexec = util.promisify( exec );

( async() => {
    const adb             = require('adbkit')
    const { exec, spawn } = require('child_process');
    const client          = adb.createClient();

    var domainsToTest = [
        'https://github.com/amoghbl1/dynamic-tripwire'
    ];

    if (CHINA_LIST) {
        domainsToTest = [
            'http://cnpolitics.org/',                   // News
            'https://ipfs.io/',                         // Anonymity
            'https://chinalawandpolicy.com/',           // Political Criticism
            'https://www.falundafa.org/',               // Religion
            'https://m.gjw.com/',                       // Alcohol and Drugs
            'https://clb.org.hk/',                      // Human Rights
            'https://twnlocalismfront.tumblr.com/',     // Terrorism and Militants
            'https://hk.sandsmacao.com/',               // Gambling
            'https://tantanapp.com/',                   // Dating
            'https://t66y.com/'                         // Pornography sharing
        ];
    }

    if (ALEXA_TOP) {
        domainsToTest = [
            'https://www.xvideos.com/',         // Adult
            'https://m.youtube.com/',           // Arts
            'https://www.office.com/',          // Business
            'https://www.google.com/',          // Computers // Regional
            'https://www.yahoo.com/',           // Regional
            'https://m.twitch.tv/',             // Games
            'https://www.nih.gov/',             // Health // Society
            'https://www.patreon.com/',         // Society
            'https://finance.yahoo.com/',       // Home
            'https://translate.google.com/',    // Kids and Teens // Science
            'https://www.researchgate.net/',    // Science
            'https://www.reddit.com/',          // News
            'https://www.booking.com/',         // Recreation
            'https://stackoverflow.com/',       // Reference
            'https://www.amazon.com/',          // Shopping
            'https://www.espn.com/'             // Sports
            // World category has no top level list.
        ];
    }

    if (INDIA_LIST) {
        domainsToTest = [
            'http://www.paktimes.com/',         // News
            'https://www.sentinelassam.com/',   // News
            'http://www.indian-elections.com/', // Political Criticism
            'https://www.hindujagruti.org/',    // Religion
            'http://www.aardip.org/',           // Human Rights
            'http://www.cis-india.org/',        // Terrorism and Militants
            'http://mate4all.com/',             // Dating
            'https://trulymadly.com/',          // Dating
            'https://www.xnxx.com',             // Pornography
            'https://www.pornhub.com/'          // Pornography
        ];
    }

    if (RUSSIA_LIST) {
        domainsToTest = [
            'http://ipvnews.org/',              // News
            'http://noblockme.ru/',             // Anonymity
            'https://uapolitics.com/',          // Political Criticism
            'http://buddhist.ru/',              // Religion
            'http://www.nodrugs.ru/',           // Alcohol and Drugs
            'https://roskomsvoboda.org/',       // Human Rights
            'https://hunafa.com/',              // Terrorism and Militants
            'https://lotoru.com/',              // Gambling
            'http://bride.ru/',                 // Dating
            'https://pornoelena.net/'          // Pornography sharing
        ];
    }

    if (FINGERPRINT_TEST) {
        domainsToTest = ['https://antoinevastel.com/bots/'];
    }

    if (PASS_FAIL) {
        domainsToTest = ['http://10.42.0.1/index.html'];
    }

    const devices = await client.listDevices(); // Moving to working with just one device
    const device = devices[0];
    const apks = JSON.parse( fs.readFileSync(APKS_JSON).toString() );
    apks.sort();

    // Setup all required folders
    let folders = [
        RESULTS_BASE_DIR,
        RESULTS_DIR,
        LOGS_DIR,
        SCREENSHOTS_DIR,
        BASELINE_DIR,
        BASELINE_SCREENSHOTS_DIR
    ];
    for(let f of folders) {
        if ( !fs.existsSync(f) ) {
            fs.mkdirSync(f);
        }
    }

    const resumeIndex = 0; // ONLY MODIFY LOCALLY FOR RESTARTS
    const apksToTest = apks;
    var apkCounter = 0;


    if (!MANUAL_TEST) {
        var slackMessenger = setInterval(function() {
            sendSlack(`${DATE}: Done with ${apkCounter} of ${apksToTest.length}`);
        }, 10 * 60 * 1000);
    }

    console.log(`Testing ${apksToTest.length} apk(s)`);
    console.log("Remember to add identifiers android id:");
    await pexec(`adb shell settings get secure android_id`);
    for (let {app_hash, package_name} of apksToTest) {

        // Skip forward tested apks if necessary.
        if(apkCounter < resumeIndex) {
            apkCounter += 1;
            console.log(`Skipping ${apkCounter}, ${package_name} / ${app_hash}`);
            continue;
        }

        if (!PASS_FAIL && (apkCounter % 50 == 0)) {
            // Can skip if it's a pass fail test.
            // We just need to do this once, not necessary if we're resuming a test.
            await establishBaseline(client, device.id, domainsToTest, BASELINE_PACKAGE_NAME, apkCounter);
        }
        apkCounter += 1;

        // Restart adb every few iterations.
        if(apkCounter % 25 == 0) {
            console.log("Killing adb...");
            await pexec("adb kill-server");
            console.log("Done killing...");
        }

        console.log(`Testing ${apkCounter} of ${apksToTest.length}`);

        const filePath = `./apks/${package_name}-${app_hash}.apk`;
        try {
            if(fs.existsSync(filePath)){
                console.log(`APK: ${package_name}-${app_hash} found on disk...`);
            } else {
                console.log(`APK: ${package_name}-${app_hash} not found on disk!! Skipping...`);
                continue;
            }
        } catch (err) {
            console.log(err);
        }

        console.log(`Installing...`);
        let installFail = false;
        await pexec(`adb -s ${ device.id } install -g ${ filePath }`).catch((error) => {
            console.error(`Installation failed: ${error}`);
            installFail = true;
        });
        if(installFail) continue; // Lets skip the failed apk.

        // Start fsmon, even before install to be safe.
        const fsmon = startFsmon();
        console.log(`Device: ${ device.id }`);

        // Just mainAction to test, not a set of actions!
        // Don't see a problem with having one set of logs for multiple websites and same browser.
        console.log('Testing 1: Launch pages without closing between activities');
        await startMitm(`${ package_name }-${ app_hash }`, false);
        await clearLogcat();

        const [mainActivity, mainAction] = await extractMain(client, device.id, package_name);
        // Start the app and decide whether to run startup heuristics or wait for user.
        // Let's launch for heuristics, the main action.
        await client.shell(device.id, `am start -a ${mainAction} -n ${mainActivity}`).catch(async () => {
            console.log("am start activity failed :/");
        });
        if (MANUAL_TEST) {
            var answer = "";
            while(answer != "c") answer = await manualIntervention();
        } else {
            let startupScreenshot = `./${SCREENSHOTS_DIR}/${package_name}-${app_hash}-startup.png`;
            await startupHeuristics(client, device.id, startupScreenshot);
        }

        // Extract the activity that needs to be launched.
        const [activity, action] = await extractActivity(client, device.id, package_name);
        if(activity == '' || action == '') {
            console.log(`Activity/Action not resolved :/ Activity: ${activity}, Action: ${action}`);
            await client.uninstall( device.id, package_name ); // Uninstall the app.
            await stopMitm();
            await stopFsmon(fsmon, `${package_name}-${app_hash}`);
            continue; // Skip the failed extraction activity
        }
        console.log(`Launching activity: ${activity}, with action ${action}`);

        let appNodeStats = {};
        let pageStats = {};
        for (let domain of domainsToTest) {
            let pageloadStart = new Date();
            let screenshotFile = `./${SCREENSHOTS_DIR}/${package_name}-${app_hash}-${domain.replace(/\//g, '')}.png`;
            console.log(`Running: am start -a ${ action } -n ${ activity } -d ${ domain }`)
            await client.shell(device.id, `am force-stop ${package_name}`);
            await sleep(500);
            await client.shell( device.id, `am start -a ${ action } -n ${ activity } -d ${ domain }` ).catch(async () => {
                console.log('am start activity failed :/');
                await stopMitm();
                await client.uninstall( device.id, package_name );
                await writeScreenshot(client, device.id, screenshotFile);
            });
            console.log('Awaiting uploadSignal...');
            let success = await uploadSignal(domain, 60000);
            pageStats["loadtime"] = new Date() - pageloadStart;
            pageStats["result"] = success;
            // Take a screenshot regardless of heuristics pass fail
            await writeScreenshot(client, device.id, screenshotFile);

            await client.shell(device.id, `input tap 500 1850`); // Home button
            await client.shell(device.id, `input tap 100 1850`); // Back button
            await sleep(1000);
            appNodeStats[domain] = pageStats;
        }
        // Save page stats
        fs.writeFileSync(`./${LOGS_DIR}/${package_name}-${app_hash}-pageload.json`, JSON.stringify(appNodeStats));
        saveLogcat(`${package_name}-${app_hash}-test1`, false);
        await stopMitm();

        // Stop the running app
        await client.shell(device.id, `am force-stop ${ package_name }` );

        // Try to suppress dialogues that may arise from stopping the app
        await suppressDialogues(client, device.id);

        console.log('Done running tests...');
        console.log('Sync sdcard...');
        await saveSDCard();
        console.log('Uninstalling...');
        await client.uninstall( device.id, package_name );
        // Stop fsmon after uninstall.
        await stopFsmon(fsmon, `${package_name}-${app_hash}`);
    }
    // Done running all apk tests.
    // Stop status update messenger.
    if (!MANUAL_TEST) clearInterval(slackMessenger);
    sendSlack('Done with all tests!');
})();

function consoleDebug(m) {
    if(DEBUG) {
        console.log(m);
    }
}

async function manualIntervention() {
    const rl = readline.createInterface({
        input:  process.stdin,
        output: process.stdout,
    });

    // Let's beep to get user attention.
    await exec('beep -l 1000');

    return new Promise(resolve => rl.question("Enter 'c' to continue once onboarding is complete...", ans => {
        rl.close();
        resolve(ans);
    }))
}

async function extractActivity(client, id, package_name) {
    return new Promise((resolve, reject) => {
        let result = Buffer.from('');
        client.shell(id, `pm dump ${ package_name }`, ( err, output ) => {
            output.on('data',  (buf) => result = Buffer.concat([result, buf]));
            output.on('error', reject);
            output.on('end',   () => {
                const str = result.toString();
                const httpaActRegex = new RegExp(`http:\n.* (${package_name}.*) filter.*\n.*Action: "(.*)"`);
                const results = str.match(httpaActRegex);
                if(results) resolve([results[1], results[2]]);
                resolve(['', '']);
            });
        });
    });
}

async function extractMain(client, id, package_name) {
    return new Promise((resolve, reject) => {
        let result = Buffer.from('');
        client.shell(id, `pm dump ${package_name}`, (err, output) => {
            output.on('data',  (buf) => result = Buffer.concat([result, buf]));
            output.on('error', reject);
            output.on('end',   () => {
                const str = result.toString();
                const mainActRegex = new RegExp(`MAIN:\n.* (${package_name}.*) filter.*\n.*Action: "(.*)"`);
                const results = str.match(mainActRegex);
                if(results) resolve([results[1], results[2]]);
                resolve(['', '']);
            });
        });
    });
}

async function startupHeuristics(client, id, screenshot) {
    // Sweet start heuristics.
    // Launch app and close it and hit buttons to prevent startup screens/dialogues.
    console.log("Startup heuristics");
    // Take a startup screenshot
    await writeScreenshot(client, id, screenshot);
    await sleep(1000);
    await client.shell(id, `input tap 500 1850`); // Home button
    await client.shell(id, `input tap 100 1850`); // Back button
    await sleep(1000);
}

async function suppressDialogues(client, id) {
    // Try some things to suppress dialogues
    await client.shell(id, `input tap 500 1850`); // Home button
    await sleep(250);
    await client.shell(id, `input tap 500 950`); // Force close / Stop
    await sleep(250);
    await client.shell(id, `input tap 100 1850`); // Back button
}

function writeScreenshot(c, d, s) {
    consoleDebug(`Writing screenshot`);
    return c.screencap(d).then(function(stream) {
        stream.pipe(fs.createWriteStream(s));
    });
}

async function startMitm(logname, baseline){
    console.log(`Starting MITM Proxy via control script...`);
    if (baseline === true) {
        return exec(`${MITM_CTRL} start ${BASELINE_DIR} ${logname}`);
    } else {
        return exec(`${MITM_CTRL} start ${RESULTS_DIR} ${logname}`);
    }
}

function stopMitm(){
    console.log('Stopping MITM Proxy via control script');
    return exec(`${MITM_CTRL} stop`);
}

function clearLogcat(){
    console.log('Clearing all logcat logs');
    return exec('adb logcat -b all -c');
}

function saveLogcat(f, baseline){
    console.log('Saving all logcat logs');
    if (baseline === true) {
        return exec(`adb logcat -d > ./${BASELINE_DIR}/${f}.logcat`);
    } else {
        return exec(`adb logcat -d > ./${LOGS_DIR}/${f}.logcat`);
    }
}

function startFsmon(){
    const cp = require('child_process');
    console.log("Starting fsmon to log file changes.");
    return cp.exec(`adb shell "${FSMON} -J /sdcard/ > ${FSMON_LOG}"`);
}

function stopFsmon(fsmon, outfile){
    console.log("Stopping fsom.");
    fsmon.kill();
    // Also exfil this and save it somewhere.
    exec(`adb pull ${FSMON_LOG} ./${LOGS_DIR}/${outfile}.fsmon`);
}

function saveSDCard(){
    console.log(`Syncing sdcard before uninstall ${RESULTS_DIR}`);
    exec(`adb-sync --reverse --times /sdcard/ ${RESULTS_DIR}/sdcard/`);
}

async function uploadSignal(domain, timeout){
    return new Promise((resolve, reject) => {
        const server = net.createServer((sock) => {
            sock.on('data', (d) => {
                console.log("Upload trigerred");
                const msg = proto.MITMMessage.deserializeBinary(d);
                let outcome = msg.getUploadreceived();
                let triggerDomain = msg.getDomain();
                console.log(`Domain: ${domain}, Trigger: ${triggerDomain}`);
                if(outcome === true) {
                    if (domain.includes(triggerDomain)) {
                        console.log("Successful injection, mitm upload triggered.");
                        server.close();
                        resolve(true);
                    } else {
                        console.log("Old domain trigger, just gonna chill and wait for a valid one.");
                    }
                } else {
                    console.log("Weird, how did this become false o.O");
                    server.close();
                    resolve(false);
                }
                sock.destroy();
            });
        });
        server.listen({
            host: 'localhost',
            port: SIGNALING_PORT,
            exclusive: true
        });
        if (timeout > 0) {
            setTimeout(() => {
                server.close();
                resolve(false);
            }, timeout);
        }
    });
}

async function establishBaseline(client, id, domainsToTest, package_name, baseline_number) {
    // Assumes package is already isntalled on the device.
    const [activity, action] = await extractActivity(client, id, package_name);
    console.log(`Baseline: ${activity} and ${action}`);
    console.log(`Establishing the baseline for the test: ${domainsToTest.length} domains...`);
    console.log(`Device: ${id}`);
    const BASELINE_LOG_NAME = `${baseline_number}-${package_name}`;
    await startMitm(BASELINE_LOG_NAME, true);
    await clearLogcat();
    for(let domain of domainsToTest){
        console.log(`Cache run: ${ domain }`);
        await client.shell(id, `am start -a ${action} -n ${activity} -d ${domain}` ).catch(async () => {
            console.log('am start activity failed :/');
            await stopMitm();
        });
        console.log('Awaiting uploadSignal from baseline crawl...')
        // Wait however long, first load has a lot of network delays and is necessary for later html comparision.
        await uploadSignal(domain, 0);
        // Take a screenshot
        await writeScreenshot(client, id, `./${BASELINE_SCREENSHOTS_DIR}/${BASELINE_LOG_NAME}-${domain.replace(/\//g, '')}.png`);
    }
    saveLogcat(BASELINE_LOG_NAME, true);
    await stopMitm();
    await client.shell(id, `am force-stop ${package_name}`);
    await fs.copyFile(`${BASELINE_CACHE}-${baseline_number}`, CACHE_FILE, (err) => {
        if (err) console.log("Failed to copy cache file!! ABORT!!!!!!!!!!!");
        else console.log("Cache file successfully copied!!");
    });
}

async function sendSlack(m){
    const { IncomingWebhook } = require('@slack/webhook');
    var url;
    try {
        url = fs.readFileSync('.slackHook').toString();
        const wh = new IncomingWebhook(url);
        console.log('Sending slack message');
        await wh.send({text: `${m}`});

    } catch (err) {
        if(err.code == 'ENOENT') {
            consoleDebug('No slack hook file found. Configure for slack messages!');
        }
        else
            console.log(err.toString());
    }
}
