# Browser Tester

Our browser testing framework is designed to test android browsers, on physical
android devices and to drive them to visit websites.
Thus we use a number of tools to achieve this.

![Overview of the analysis framework](/figures/dynamic_analysis_components.jpg "Dynamic Analysis Framework")

For more details about the functionality of each component, please refer
Section 4.2 "Dynamic Analysis" of our [paper](placeholder_link).

This codebase implements the "Director" and "Gateway" in the above figure, as
well as other glue required to perform tests.

## Requirements

1. `iptables`
2. `mitmproxy`
3. `adb`
4. `nodejs`
5. `python3`
6. `python3-pip`
7. `npm`
8. `adb-sync`
9. `protoc`

## Network setup

In order for transparent proxying to work, we require two network interfaces on
the machine running the tests.

One interface connected to the internet (wired or wireless); the other,
configured as a WiFi hotspot to which the test android device is connected.

This second interface is configured as the `MITM_INTERFACE` variable in the
`mitmproxy-ctrl` script.

## Other requirements

Each of the subsections here goes over a tool that is required to make different pieces of `dynamic-tripwire` work in order to successfully test android browsers.

### apks.json

Each browser to be tested is supplied to `android-flow.js` as an [Android Package file](https://en.wikipedia.org/wiki/Apk_(file_format)).
Since different versions of an APK might want to be tested, we use `package_name-app_hash.apk` as a unique identifier for an APK to be tested.
Here, `app_hash` is a [SHA 256](https://en.wikipedia.org/wiki/SHA-2) hash of the APK file.

An example of this can be found here](apk_lists/apks.json).
In this case, `android-flow.js` would look for the APK `dynamic.test.package.name` with hash `APK_HASH` in the apks folder.
Thus, it would look for `apks/dynamic.test.package.name-APK_HASH.apk` file to install and test on the physical device.

The `APK_HASH` is not verified to be the hash of the APK, but the convention is used since this it is easy to distinguish versions using this.

### android-flow.js
The android-flow script expects apks to be in the `apks` folder and for them to
be specified in the `apks.json` file.
Once this is set up, this node script drives all the tests, the code is made
readable to figure out what it does.

### mitmproxy-ctrl
This script manages `mitmdump` and `iptables` to allow transparent proxy
capabilities on a selected network interface.

Follow these steps to configure the script.
1. Edit the `MITM_INTERFACE` variable in the script to the interface of your
choice.
2. Run the script `./mitmproxy-ctrl start test test`, to create the default
directories (mitm-conf and mitm-logs) and to make sure you don't run into
errors.

Following these steps should make sure that all network requests coming in on
the configured interface pass through mitm proxy, which can be verified by going
through the log files.

### Protobuf
Dynamic tripwire uses
[Protocol Buffers](https://developers.google.com/protocol-buffers) for messages
sent from `mitmproxy` to `nodejs`.
For this to function, we need `protoc` installed, please follow
[these instructions](https://github.com/protocolbuffers/protobuf#protocol-compiler-installation)
or platform specific instructions to install this.

Once installed, run the makefile in the `protocs` folder to generate the
required protobuf files.

### Play protect
Depending on the version of Android running on the test device, it might have
Google Play Protect enabled, which is a feature of the `Play Store` application.
Disabling this is necessary as it blocks the installation of some applications.

### For Mitmproxy and extension
1. Install aforementioned requirements.
2. Setup mobile device to use the base machine's hotspot, which is mitm'd.
3. `git clone https://github.com/amoghbl1/dynamic-tripwire`
4. `pip install -r requirements`

### For Node
1. `npm install`

### Protobuf
1. Run `make` in the `protocs` folder

This is required to generate the necessary protobuf files.

## Steps to launch tests
A general guideline to launch a test.

1. Factory reset the device
2. Disable play protect on the test device
3. Enable USB Debugging
4. Enable Stay awake
5. Install MITM certificate
6. Connect to the Wifi
7. Install fsmon to `/data/local/tmp/`
8. Set up baseline browser
9. Populate `grep_pii.json` with identifiers related to this run
10. Set up `apks.json` and make sure files are in the apks folder
11. Launch tests, `node android-flow.js`

Once the node script is launched, the console output should indicate the state
of the tests.

The `android-flow.js` file is the entrypoint and driver of the process.
Spawning mitmproxy and other necessary resources to be used during
experimentation.

## Stats Helper

To process all the data collected during these tests, we have a number of python
files in `stats_scripts` which are all driven through a shell script
`statsHelper`.

Run `./statsHelper` to get a brief understanding of what different processing
options are available.

For the scripts themselves, reading code is the only way to figure out what they
do.
