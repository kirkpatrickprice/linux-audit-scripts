# kpnixaudit #

This script is used by KirkpatrickPrice auditors to collect information from Linux hosts.  Unlike many other tools out there, the approach used in this script is "keep it lite":
* Keep it simple -- there is only one file that is needed -- `kpnixaudit.sh`.  Everything runs from there.
* Keep it simple -- the script tries not to use any crazy Bash-fu.  Comments are embedded througout to facilitate DevOps, Site Reliability and other engineers' review prior to running it on your server
* Use only commands that are already built into the operating system (no Python, Perl, jq, etc required)
* In addition to built-in OS commands, only use commands that will only be present if the software that we're auditing is installed -- e.g. 
    * Docker ==> `docker`
    * Kubernetes ==> `kubectl`
    * Tripwire ==> `twadmin`
* Minimal real-time analysis -- we collect data for off-line analysis and don't report findings during data collection.  This keeps the dependencies to a minimum and the logic simple, especially important for running the script on production machines.
* Fail quietly -- If a command isn't found or the piece of software isn't installed, note that in the output and keep going

Starting with version 0.6.12, all Git Commits are signed to increase reliability that code hasn't been changed by anyone but KirkpatrickPrice.  You can verify the signature of any commit by clicking on the commit message or hash ID and noting that "Verified" is indicated.

## Critical dependencies ##
* Shell: `bash`
* Package managers: Combinations of `dpkg` `rpm` `yum` `apt`
* Service management: `systemctl` `service` `chkconfig`
* Hardened kernel: `selinux` or `apparmor`
* Misc. commands:   `find` `which` `echo` `awk` `uname` `sysctl` `grep` `useradd` `head` `tail` `netstat` `initctl` `launchctl`
* Product-specific commands: `docker` `kubectl` etc.  if installed

The script has been tested against currently-supported distributions of:
* Ubuntu -- 18.04LTS and 20.04LTS
* RHEL and CentOS -- version 7.x and 8.x
* Amazon Linux -- Versions 1 and 2

It will also likely run well on any other RPM- or DEB-based distribution that supports the dependencies above.

## Installation
Installation is as simple as copying or cloning the Bash script to your system.

`git clone https://github.com/kirkpatrickprice/linux-audit-scripts`

or using wget:

`wget https://raw.githubusercontent.com/kirkpatrickprice/linux-audit-scripts/main/kpnixaudit.sh`

or click on the script and download the raw file.

## Usage and Results
```
USAGE:
        kpnixaudit.sh [ -cdhw ] [-m module ...]
        Options:
            -c      Print DumpCmd errors messages to STDERR instead of redirecting them to /dev/null
            -d      Print DEBUG messages to STDOUT and to REPORT_NAME
            -m      Select modules to run.  Use -m multiple times to select more than one module
                    If not used, all modules will be run.  If used, only the selected modules will be
                    run.  To run all modules except for WorldFiles, use the -w switch.  Module names
                    are CaSe SeNsItIvE.
                    Valid modules: System Network Security Logging Users K8sMaster K8sWorker Docker WorldFiles
            -w      Disable the WorldFiles module (this check can take a long time on systems
                    with lots of network-attached storage such as NFS mounts).
            -h      this help

        NOTE: This script must be run as ROOT
```
The most common usage is:
`sudo ./kpnixaudit.sh`

Although your auditor may ask you to run only certain modules (e.g.):
`sudo ./kpnixaudit.sh -m System -m Security`

The end result is a text file named as `hostname.txt`.  Your auditor will ask you to upload all of the files from the identified sample as a ZIP to the Online Audit Manager portal.
