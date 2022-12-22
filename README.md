# Browser Tester

Our browser testing framework is designed to test android browsers, on physical
android devices and to drive them to visit websites.
Thus we use a number of tools to achieve this.

![Overview of the analysis framework](/figures/dynamic_analysis_components.pdf "Dynamic Analysis Framework")

## Requirements

1. `iptables`
2. `mitmproxy`
3. `adb`
4. `nodejs`
5. `python3`
6. `python3-pip`
7. `npm`
8. `adb-sync`

## Network setup

In order for transparent proxying to work, we require two network interfaces on
the machine running the tests.

One interface connected to the internet (wired or wireless); the other,
configured as a WiFi hotspot to which the test android device is connected.

This second interface is configured as the `MITM_INTERFACE` variable in the
`mitmproxy-ctrl` script.

## Set up requirements
### apks.json
The APKs to be tested are defined in a json file, and also have to be named in a
format using properties in this json file.
The file itself is a list of objects containing at least 2 properties `app_hash`
and `package_name`.
An example can be found [here](apk_lists/apks.json).

The corresponding apks are expected to be in the `apks` folder, in the
`package_name-app_hash.apk` format as shown
[here](apks/dynamic.test.package.name-APK_HASH.apk).

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

## Miscellaneous
### Play protect
Depending on the version of Android running on the test device, it might have
Google Play Protect enabled, which is a feature of the `Play Store` application.
Disabling this is necessary as it blocks the installation of some applications.

## Installation
### For Mitmproxy and extension
1. Install aforementioned requirements.
2. Setup mobile device to use the base machine's hotspot, which is mitm'd.
3. `git clone https://github.com/amoghbl1/dynamic-tripwire`
4. `pip install -r requirements`

## Usage
### For flow
1. `npm install`
2. Set up `apks.json` and make sure files are in the apks folder.
3. `node android-flow.js`
4. `wait for a wile`

The android-flow.js file is the entrypoint and driver of the process.
Spawning mitmproxy and other necessary resources to be used during
experimentation.

## Steps to launch tests
A general guideline to launch a test.

1. Factory reset the device.
2. Disable play protect on the test device.
3. Enable USB Debugging.
4. Enable Stay awake.
5. Install MITM certificate.
6. Connect to the Wifi.
7. Install fsmon to `/data/local/tmp/`
8. Apply any local changes to the test code if needed.
9. Set up VPN for the base machine.
10. Set up baseline browser.
11. Populate `grep_pii.json` with identifiers related to this run.
12. Launch tests, `node android-flow.js`.

## Stats Helper

To process all the data collected during these tests, we have a number of python
files in `stats_scripts` which are all driven through a shell script
`statsHelper`.

Run `./statsHelper` to get a brief understanding of what different processing
options are available.

For the scripts themselves, reading code is the only way to figure out what they
do.
