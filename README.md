# dynamic-tripwire

## Requirements

1. `iptables`
2. `mitmproxy`
3. `adb`
4. `nodejs`
5. `python3`
6. `adb-sync`

## Network setup

In order for transparent proxying to work, we require two network interfaces on the machine running the tests.

One interface connected to the internet (wired or wireless); the other, configured as a WiFi hotspot to which the test android device is connected.

This second interface is configured as the `MITM_INTERFACE` variable in the `mitmproxy-ctrl` script.

## Set up requirements
### get-apks.sh
The get-apks script uses ssh to fetch information about the list of apks stored on golem.
To use this, ssh needs to be configured as follows:
```
Host golem
    HostName golem.homezone-project.com
    Port 27
    IdentityFile <SSH_KEY_TO_BE_USED>
    User <USERNAME_HERE>
```
### android-flow.js
The android-flow script uses scp to download apks from the server, an ssh setup similar to the previous requirement, to the same server is needed for this script to function properly.

### mitmproxy-ctrl

This script manages `mitmdump` and `iptables` to allow transparent proxy capabilities on a selected network interface.

Follow these steps to configure the script.
1. Edit the `MITM_INTERFACE` variable in the script to the interface of your choice.
2. Run the script `./mitmproxy-ctrl start test test`, to create the default directories (mitm-conf and mitm-logs) and to make sure you don't run into errors.

Following these steps should make sure that all network requests coming in on the configured interface pass through mitm proxy, which can be verified by going through the log files.

## Miscellaneous
### Play protect

Depending on the version of Android running on the test device, it might have Google Play Protect enabled, which is a feature of the `Play Store` application.
Disabling this is necessary as it blocks the installation of some applications.

## Installation
### For Mitmproxy and extension
1. Install aforementioned requirements.
2. Setup mobile device to use the base machine's hotspot, which is mitm'd.
3. `git clone https://git.homezone-project.com/feal94/mobile-browsers-scripts.git`
4. `pip install -r requirements`

## Usage
### For flow
1. `npm install`
2. `./get-apks.sh`
3. `node android-flow.js`
4. `wait for a wile`

the android-flow.js file is the entrypoint and mastermind of the process. Spawning mitmproxy and other necessary resources to be used during experminetation

Known issues:
* Many apps crash or do not open
* Single page apps cause issues as they send javascript or a base html file which will be quite different from what gets rendered. So comparing the mobile rendered html against the post processed will give a  more accurate result
* The activity or action used for an app may not be correct maybe there are better ways to find these

Next steps:
  * simulate devices to test preinstalled apks

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
