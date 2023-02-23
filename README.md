# Browser Tester

Our browser testing framework is designed to test android browsers, on physical
android devices and to drive them to visit websites.
Thus we use a number of tools to achieve this.

![Overview of the analysis framework](/figures/dynamic_analysis_components.jpg "Dynamic Analysis Framework")

This code is to be run on a machine that acts as the "base machine" and implements functionality of the "Director" (1) and "Gateway" (2) to perform tests on a physical "Test device" (3).

The base machine is connected to the internet on one network interface and has another network interface set up as a hotspot (which the test device connects to).
All network traffic from the test device is routed to a `mitmporoxy` instance running on the base machine, which intrercepts, records, and/or modifies requests/responses.
The test device is also connected to the base machine via adb over USB to allow the machine to install/uninstall browser apps, and drive them to visit webpages.

For more details about the functionality of each component, please refer
Section 4.2 "Dynamic Analysis" of our [paper](https://arxiv.org/pdf/2212.03615.pdf).

# Requirements

Since this codebase has a lot of moving parts, we differentiate the requirements.

- **Tool requirements**: tools/libraries required to run the codebase
- **Network setup**: network configutation for the base machine
- **Test device setup**: how to configure a test device
- **Setup files**: infromation/files required to run the codebase

## Tool requirements

1. `iptables`
2. `mitmproxy`
3. `adb`
4. `nodejs`
5. `python3`
6. `python3-pip`
7. `npm`
8. `adb-sync`
9. `protoc`

Now we go over some notes for setting up these tools.

### Mitmproxy

`pip install -r requirements`

### Node

`npm install`

### Protobuf
Dynamic tripwire uses
[Protocol Buffers](https://developers.google.com/protocol-buffers) for messages
sent from `mitmproxy` to `nodejs`.
For this to function, we need `protoc` installed, please follow
[these instructions](https://github.com/protocolbuffers/protobuf#protocol-compiler-installation)
or platform specific instructions to install this.

Run `make` in the `protocs` folder

## Network setup (Base machine)

In order for transparent proxying to work, we require two network interfaces on
the base machine running the tests.

One interface connected to the internet (wired or wireless); the other,
configured as a WiFi hotspot to which the test android device is connected.

This second interface is configured as the `MITM_INTERFACE` variable in the
`mitmproxy-ctrl` script.

## Android Device Setup
### Play protect
Depending on the version of Android running on the test device, it might have
Google Play Protect enabled, which is a feature of the `Play Store` application.
Disabling this is necessary as it blocks the installation of some applications.

### Hotspot
Make sure to connect the android test device to the base machine hotspot.

### Baseline browser
The baseline browser is used to get baseline results when visiting a website.
This browser needs to be installed on the test device before any tests are run.

The package name of the browser needs to be set in `android-flow.js` in the `BASELINE_PACKAGE_NAME` constant.
In our tests and codebase we use the package `com.homezoneproject.mywebviewapp`.
This can be replaced with any browser `com.android.chrome` for instance.

Please refer the paper for details about the baseline browser and how results are compared with it.

## Setup files

Each of the subsections here goes over a setup file required to run this codebase.

### apks.json

Each browser to be tested is supplied to `android-flow.js` as an [Android Package file](https://en.wikipedia.org/wiki/Apk_(file_format)).
Since different versions of an APK might want to be tested, we use `package_name-app_hash.apk` as a unique identifier for an APK to be tested.
Here, `app_hash` is a [SHA 256](https://en.wikipedia.org/wiki/SHA-2) hash of the APK file.

An example of this can be found here](apk_lists/apks.json).
In this case, `android-flow.js` would look for the APK `dynamic.test.package.name` with hash `APK_HASH` in the apks folder.
Thus, it would look for `apks/dynamic.test.package.name-APK_HASH.apk` file to install and test on the physical device.

The `APK_HASH` is not verified to be the hash of the APK, but the convention is used since this it is easy to distinguish versions using this.

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

### android-flow.js
The android-flow script expects apks to be in the `apks` folder and for them to
be specified in the `apks.json` file.
Once this is set up, this node script drives all the tests, the code is made
readable to figure out what it does.

### grep_pii.json

A file to track the different personally identifiable information we look for in network requests.
In our tests, we look for PII like:
- IMEI
- Android advertisement IDs
- Android ADB IDs
- MAC addresses
- List of installed packages
- ...

This is not an exhaustive list.
Based on the type of app being tested and what is expected in the network traffic, this list  will change.
The goal of this is not to detect all such PII but look for specific PII in intercepted traffic.
All code in `statsHelper` uses this knowledge to compile numbers for tests.

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
