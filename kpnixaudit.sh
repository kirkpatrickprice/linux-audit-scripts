#!/bin/bash

# Copyright 2024 KirkpatrickPrice, Inc.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# KirkpatrickPrice *nix Audit Script
# Author: Randy Bartels (original version by Michael Fowl)
# Usage example: "sudo ./kpnixaudit.sh" to audit common configs and setting on *nix environments.  Developed and
# tested against CentOS/RHEL 7 and 8, Amazon Linux 1 and 2 and Ubuntu 1804 and 2004 distributions, but should work
# reasonably well on similar distributions as long it supports any of the following:
# Critical dependencies:
#   - Shell:            Bash
#   - Package managers: Combinations of dpkg, rpm, yum and apt
#   - Service manager:  systemctl, service, chkconfig
#   - Hardened kernel:  SELinux or AppArmor
#   - Misc. commands:   find, which, "echo -e", awk, uname, sysctl, grep, useradd, head, tail, netstat, initctl, launchctl
#                       svc, auditctl

# A report titled "hostname".txt will be generated in the working directory.
# NOTE: The script must be run as ROOT


# CHANGELOG
# Version 0.3:
#   - implemented check for root user
#   - Updated apt check to display verbose version information on upgradeable packages
#   - Changed "REPORT_NAME" to drop the "-system-report" suffix as this only made it harder to grep the results later
# Version 0.4:
#   - Added "ubuntu-support-status" call to Package Manager section
# Version 0.5:
#   - Mostly ground-up rewrite to increase supportability, update to modern distributions, add CIS benchmark references
#     and facilitate interpretation of results
#   - Introduced "header" and "footer" sections for consistent section starts/stops and improved readability
#   - Added CIS References (using CIS Distribution Independent Linux Benchmark v2.0)
#   - Added SETUID AuditD configuration checks (CIS 4.1.12)
#   - Added supported file system module checks (CIS 1.1.1.x)
#   - Added capturing file system mounts (CIS 1.1.2+)
#   - Added gathering boot loader config file permissions (CIS 1.4.1)
#   - Added capturing SUID_DUMPABLE setting for core dumps (CIS 1.5.1)
#   - Added capturing No Execute (CIS 1.5.2)
#   - Added gathering Address Space Layout Randomization (ASLR) config (CIS 1.5.3)
#   - Added gathering /etc/motd, /etc/issue and /etc/issue.net (CIS 1.7.1.x)
#   - Added collecting the first and last 25 lines of common log files
# Version 0.5.1:
#   - Added capturing OpenVPN configurations (Security_OpenVPN_Config)
#   - Added capturing OpenLDAP configurations (Security_OpenLDAP_Config)
# Version 0.5.2
#   - Added better support for NTP status using ntpq and chronyc
# Version 0.5.3
#   - Comments added to common functions (dumpcmd, svcstatus, etc) to improve readability
#   - Renamed sections for greater consistency during analysis -- Convention <Group>_<DetailUsingTitleCase> separated by an underscore
#   - Added command line -w switch to skip search for world-writable files
#   - Added prompt to confirm search for world-writable files.  Default = YES after 30 seconds
#   - Added collecting /etc/crypttab and LUKS status commands for LUKS-encrypted volumes
#   - Added better support for NTP status when using systemd-timesyncd
#   - Renamed section "Network_TimeSync" to "Network_NTP" and added suffix for ntpd, chronyd and timesyncd
#   - Limited directory search for EasyRSA and SETUID file searches
# Version 0.5.4
#   - Reverted to using a for loop for getting "passwd -S <username>" status for each user.  Not all modern platforms support the "passwd -Sa" method
#   - Cleaned up a few section names to make it easier to parse the results
#   - Collect IPSec configurations and status in "Security_IPSecConfig" and "Security_IPSecStatus" / supports anything using standard Linux "ipsec" 
#     command and /etc/ipsec.conf, /etc/ipsec.secrets and /etc/ipsec.d config methods. Tested with strongswan and libreswan.
# Version 0.5.5
#   - Collect aide.conf for the AIDE HIDS agent (Security_HidsAIDEConfig)
#   - Collect status for CrowdStrike HIDS agent (Security_HidsCrowdStrike)
#   - Collect CarbonBlack information (Security_HidsCarbonBlack)
#   - Improve password settings collection for Redhat-based systems (Users_DefaultSettings)
# Version 0.6.0
#   - Added KPNIXVERSION output to the report file
#   - Added Kubernetes sections (K8s, K8sMaster_, K8sWorker_ sections)
#   - Added Docker sections (Docker_*)
#   - Implemented the ability to run specific modules using the -m switch
#   - Changed dumpcmd to use a much simpler (at least to read) awk-based method of dumping the results to the report file
#   - Collect SNAPS info, in case they're being used on Ubuntu (System_Snaps)
# Version 0.6.1
#   - Collect package install dates for RPM- and Debian-based systems (System_PackageInstalledSoftware)
# Version 0.6.2
#   - Collect /etc/pwquality.conf.d/* in addition to /etc/pwquality.conf
#   - Collect /etc/sssd configuration files and directories
# Version 0.6.3
#   - Renamed "Network_OpenSSHsshdonfig" to "Network_OpenSSHServerConfig" to be consistent with "Client" vs "Server" sections
#   - Collect site-wide ssh_config client configuration files
# Version 0.6.4
#   - Collect /etc/subuid and /etc/subgid files to assist with Docker user namespace configurations (Users_SubuidSubgid)
# Version 0.6.5
#   - Also collect file system mounts using systemctl list-units --all --type=mount (System_FSMounts)
#   - Collect Samba configuration (Network_Shares)
#   - Report auditd service status (Logging_AuditdStatus)
#   - Get the Name Service Switch configuration (Network_NSSwitchConfig)
# Version 0.6.6
#   - Collect /etc/ssh/moduli file to demonstrate secure SSH KEX settings such as when diffie-hellman-group-exchange-sha256 is enabled
#   - Look for /etc/*/smb.conf instead of a hard-coded location
#   - Look for /etc/*/*/modsecurity.conf instead of a hard-coded location
#   - Look for /etc/*/*/sssd.conf instead of a hard-coded located
# Version 0.6.7
#   - Collect /etc/apt/apt.conf.d/* files as part of System_PackageManagerConfigs
# Version 0.6.8
#   - Fixed issue in Logging_SyslogLogrorateConfig where it missed files in the /etc/logrotate.d directory
#   - Improved IPTables collection by listing rules from FILTER, NAT and MANGLE tables (only FILTER was collected previously)
#   - Added check to list all users with an ~/.ssh/authorized_keys file (Network_OpenSSHUserAuthKeys)
# Version 0.6.9
#   - Improved the collection of package manager logs for Debian-based systems in System_PackageInstalledSoftware
#   - Added check to see if "cbagent" is running in the Security_HidsCarbonBlack section.
#   - Added more comments about why various content might be useful to auditors.
#   - Moved check for users' authorized_keys files from Network_OpenSSHUserAuthKeys to Users_AuthorizedKeys
#   - Grab nginx configurations from containers since that's a very popular container (Docker_ContainerDetails-Nginx)
# Version 0.6.10
#   - Added "ss -lptun"-based checks where "netstat" is used to support the latest Ubuntu instances (and maybe more)
#   - Added "ip route" in addition to "netstat -r" to support the latest Ubuntu instances (and maybe more)
#   - Added collection of /etc/aide/* to Security_AideConfig to be sure to grab all of the Aide configs
# Version 0.6.11
#   - Collect all /etc/bashrc, /etc/profile and /etc/profile.d files used to set user shell defaults (Users_Profile)
#   - Collect Fluentd configuration in Logging_FluentD
#   - Collect Datadog configuration in Logging_Datadog
#   - Fixed Users_BlankPasswd where it was throwing an AWK error
# Version 0.6.12
#   - Removed "last" command from Users_LoginHistory as it was unnecessary for what we're after here
#   - Added "Users_Lastlog90" to only get the usernames that haven't logged in for at least 90 days
#   - Added GPG-signed commits to increase reliability that code hasn't been changed
#   - Added version string to Usage output
# Version 0.6.13
#   - Added version output to the Usage function
#   - Cleaned up a typo in the Users_BlankPasswd check output
# Version 0.6.14
#   - Added additional checks to support Ubuntu 22.04
#   - Separated "Network_Shares" in to "Network_SharesNFS" and "Network_SharesSamba"
#   - Acquired additional NFS-related content including NFS server configs in /etc/default/nfs-*, /etc/nfs.conf and /etc/nfs.conf.d
#   - Modified svcstatus to report the current status (active/inactive/etc) when systemctl is used.
#       NOTE: This change results in both uninstalled as well as currently not-running services being reported as "inactive"
#   - Added check to list file system permissions for key log files in /var/log (Logging_LogFilePermissions)
# Version 0.6.15
#   - Changes to better facilitate working with adv-searchfor.py's YAML scripted mode
# Version 0.6.16
#   - Typos and other minor corrections
# Version 0.6.17
#   - Add command line switch to disable Kubes checks (especially useful for scripting kpnixaudit.sh)
# Version 0.6.18
#   - Collect /etc/yum.repos.d/* (System_PackageManagerConfigs)
#   - Collect /etc/krb5.conf.d/* (Users_KerberosConfig)
# Version 0.6.19 (April 6, 2023)
#   - Collect "dnf history list" (System_PacakageManagerInstalledSoftware)
#   - Collect "dnf list updates" (System_PackageManagerUpdates)
# Version 0.6.20 (May 9, 2023)
#   - Collect /etc/dnf/*.conf files (System_PackageManagerConfigs)
# Version 0.6.21 (June 21, 2023)
#   - Collect BIOS information (System_BIOS)
#   - Collect per-user crontabs located in /var/spool/cron/ (System_ScheduledJobs-<username>)
# Version 0.6.22 (Feb 14, 2024)
#   Fixed unary operator expected error in KUBES check (https://github.com/kirkpatrickprice/linux-audit-scripts/issues/22) Thanks to @knightsg

KPNIXVERSION="0.6.22"

function usage () {
    echo "
    $(basename $0) Version ${KPNIXVERSION}

    Creates a text file in ~/<hostname>.txt with system configuraiton information needed to audit Linux systems

    USAGE:
        $(basename $0) [ -cdhw ] [-m module ...]
        Options:
            -c      Print DumpCmd errors messages to STDERR instead of redirecting them to /dev/null
            -d      Print DEBUG messages to STDOUT and to REPORT_NAME
            -k      Disable Kubernetes checks
            -m      Select modules to run.  Use -m multiple times to select more than one module
                    If not used, all modules will be run.  If used, only the selected modules will be 
                    run.  To run all modules except for WorldFiles, use the -w switch.  Module names 
                    are CaSe SeNsItIvE.
                    Valid modules: ${MODULESLIST[*]}
            -w      Disable the WorldFiles module (this check can take a long time on systems
                    with lots of network-attached storage such as NFS mounts).  
            -h      this help

        NOTE: This script must be run as ROOT
    "
}

function debug () {
    # Function to print debug messages if required
    if [ $DEBUG -eq 1 ]; then
        echo -e "#[DEBUG]:: $1" | tee -a $REPORT_NAME
    fi
}

function header () {
    #Print a header message for each testing group
    #Parameters:
    #   $1 - Section Heading Name
    #   $2 - CIS Reference number

    SECTION="$1"
    echo -e ''$_{1..50}'#' >> $REPORT_NAME
    echo -e ''$_{1..50}'#' >> $REPORT_NAME
    echo -e "Checking: $1"
    echo -e "#[BEGIN]: $1" 2> /dev/null >> $REPORT_NAME
    echo -e "#[CISReference]: $2" >> $REPORT_NAME

}

function footer () {
    #Print a closing footer message for each testing group
    #Parameters:
    #   None (inherit $SECTION from "heading" function)
    
    echo -e "#[END]: $SECTION" >> $REPORT_NAME
    echo -e ''$_{1..50}'#' >> $REPORT_NAME
    echo -e ''$_{1..50}'#' >> $REPORT_NAME
    SECTION=""
}

function comment () {
    #Print comment lines preceded by "###" to make them easy to find (and grep out) when analyzing the results
    #Parameters:
    #   $1 - Comment to insert into report
    
    echo -e "###$1" 2>/dev/null >> $REPORT_NAME
}

function dumpfile () {
    #Print the output of the specified file(s) preceded by the section and file name to make the results easier to grep
    #Parameters:
    #   $1 - Path to start from -- do NOT include the trailing "/"
    #   $2 - Filespec to match against (e.g. *.conf) / requires regex syntax as this is used by 'find -iname <filespec>'
    #   $3 - Optional MAXDEPTH / assume 1 if none provided
    #       - "0" will only search the starting point passed in $1 / it won't find any files matched in $2 / DO NOT USE
    #       - "1" will search the current <path> in $1 but not recurse any directories
    #       - "2" will search the current path in $1 plus one more level of directies under that...
    #       - "3" and so on... 

    debug "Dumpfile: $1 $2 $3"
        
    if [ -n "$3" ]; then
        #If provided, set MAXDEPTH to $3
        local MAXDEPTH="$3"
    else
        #If not provided, assume MAXDEPTH is 1 (see function comments above for interpretation)
        local MAXDEPTH="1"
    fi
    
    debug "Dumpfile: $1 $2 $MAXDEPTH"

    if [ -d "$1" ]; then
        for n in $(find -L $1 -maxdepth $MAXDEPTH -type f -iname "$2"); do
            debug "Find: $n"
            comment "File contents: $n"
            
            # Use awk to format each line as SECTION::FILENAME::LINE
            awk \
                -v vSECTION="$SECTION" \
                -v vFILE=$n \
                '{
                    printf "%s::%s::%s\n",vSECTION,vFILE,$0;
                }' $n >> $REPORT_NAME
        done
    else
        debug "$1 directory does not exist"
        comment "$1 directory does not exist."
    fi
}

function redactfile () {
    #Print the output of the specified file preceded by the section and file name to make the results easier to grep
    #Redact lines that include the text provided in $2
    #Parameters:
    #   $1 - Full path of the file
    #   $2 - Regex pattern for the content that should be redacted
    #   $3 - Text to use for redaction
    # For example, if you want to replace "secret: <base64_string>" with "secret: <REDACTED>"
    #   $1 - File to process
    #   $2 - "secret:.*"
    #   $3 - "secret: <REDACTED>"

    debug "Redactfile: $1 $2 $3"

    local FILE=$1
    local PATTERN="$2"
    local REPLACE="$3"

    if [ -f "$FILE" ]; then
    # A short AWK script that finds all PATTERNs and replaces them with REPLACE
        awk \
            -v vPATTERN="$PATTERN" \
            -v vREPLACE="$REPLACE" \
            -v vSECTION="$SECTION" \
            -v vFILE=$FILE \
            '{
                gsub(vPATTERN,vREPLACE);
                printf "%s::%s::%s\n",vSECTION,vFILE,$0;
        }' $FILE >> $REPORT_NAME
    else
        debug "$1 file does not exist"
        comment "$1 file does not exist."
    fi
}

function dumpcmd () {
    #Print each line of the command's output with the section name as the prefix to make it easier to grep the results
    #Parameters:
    #    $1 - Command to process and dump results into $REPORT_NAME

    comment "Running: $1"
    debug "Running: $1"

    local COMMAND_ROOT="$(echo -e "$1" | awk '{ print $1 }')"
    local COMMAND_PATH="$(which $COMMAND_ROOT 2> /dev/null)"
    
    debug "DumpCmd: $COMMAND_ROOT==>$COMMAND_PATH"

    if [ -n "$COMMAND_PATH" ]; then
        if [ $DEBUGCMD = 0 ]; then 
            local RESULTS="$(${1} 2> /dev/null)"
        else
            local RESULTS="$(${1})"
        fi

        echo "$RESULTS" | awk -v vSECTION=$SECTION '{ printf "%s::%s\n",vSECTION,$0; }' >> $REPORT_NAME

    else
        comment "$COMMAND_ROOT command not found."
    fi
}

function dumpgrep () {
    #Using grep/zgrep, dump lines matching $1 in files matching fileglob in $2
    #Parameters:
    #   $1 - Regex to use for matching
    #   $2 - Path to start from -- do NOT include the trailing "/"
    #   $3 - Filespec to match against (e.g. *.conf) / requires regex syntax as this is used by 'find -iname <filespec>'
    #   $4 - Optional MAXDEPTH / assume 1 if none provided
    #       - "0" will only search the starting point passed in $1 / it won't find any files matched in $2 / DO NOT USE
    #       - "1" will search the current <path> in $1 but not recurse any directories
    #       - "2" will search the current path in $1 plus one more level of directies under that...
    #       - "3" and so on... 

    local FILE
    local PATTERN=$1
    local SEARCHPATH=$2
    local FILESPEC=$3

    if [ -n "$4" ]; then
        #If provided, set MAXDEPTH to $3
        local MAXDEPTH="$4"
    else
        #If not provided, assume MAXDEPTH is 1 (see function comments above for interpretation)
        local MAXDEPTH="1"
    fi

    debug "DumpGrep: Pattern:\"$PATTERN\" PATH:$SEARCHPATH FILESPEC:\"$FILESPEC\" DEPTH:$MAXDEPTH"

    for FILE in $(find -L $SEARCHPATH -maxdepth $MAXDEPTH -type f -iname "$FILESPEC" | sort); do
        case $FILE in
            *.gz ) 
                local CMD="zgrep"
                ;;
            * )
                local CMD="grep"
                ;;
        esac

        comment "Running: $CMD \"$PATTERN\" $FILE"
        debug "Running: $CMD \"$PATTERN\" $FILE"
        
        local COMMAND_ROOT="$(echo -e "$CMD" | awk '{ print $1 }')"
        local COMMAND_PATH="$(which $COMMAND_ROOT 2> /dev/null)"
        
        debug "DumpCmd: $COMMAND_ROOT==>$COMMAND_PATH"

        if [ -n "$COMMAND_PATH" ]; then
            if [ $DEBUGCMD = 0 ]; then 
                local RESULTS="$($CMD "$PATTERN" "$FILE" 2> /dev/null)"
            else
                local RESULTS="$($CMD "$PATTERN" "$FILE")"
            fi

            echo "$RESULTS" | awk -v vSECTION=$SECTION -v vFILE=$FILE '{ printf "%s::%s::%s\n",vSECTION,vFILE,$0; }' >> $REPORT_NAME

        else
            comment "$COMMAND_ROOT command not found."
        fi
    done
}


function svcstatus () {
    #Determine the correct method of reporting daemon status.  Prefer "systemctl is-enabled <service_name>" but fall back to "service <service_name> status" is systemctl is not available.
    #Paramaters:
    #    $1 - Name of service to check

    debug "SvcStatus: $1"
    local CMD=""

    comment "Checking status: $1"

    #If systemctl is available, use it
    if [ -n "$(which systemctl 2> /dev/null)" ]; then
        local CMD="systemctl is-active $1"
    else
        #If systemctl is not available, but the service command is, then use it
        if [ -n "$(which service 2> /dev/null)" ]; then
            local CMD="service $1 status"
        fi
    fi

    #If CMD was set by either condition above, process the results
    if [ -n "$CMD" ]; then
        local STATUS="$($CMD 2> /dev/null)"
        # If STATUS is "blank" (e.g. systemctl or service commands didn't find the service), then set STATUS to "not found"
        if [ -z "$STATUS" ]; then
            local STATUS="NOTFOUND"
        fi

        #Return the results
        echo -e "$SECTION:: $1_status: $STATUS" >> $REPORT_NAME
    else
        comment "Systemctl and service commands not found.  Unable to verify $1 status."
    fi
}

function getSubString () {
    #Function to search the global STRING variable to find the substring when provided with the following paramaters:
    #    $1 - Prefix string (include any glob characters such as *<text>)
    #    $2 - Suffix string (include any glob characters such as <text>*)
    #All text between and exclusive of PREFIX and SUFFIX will be put back into the SUBSTRING global variable

    local PREFIX=$1
    local SUFFIX=$2
    local TEMP=""

    debug "STRING: '$STRING'"
    debug "PREFIX: '$PREFIX'"
    debug "SUFFIX: '$SUFFIX'"

    # Use BASH parameter substitution to eliminate the text before the PREFIX and after the SUFFIX (inclusive).  Return what's left as SUBSTRING
    local TEMP=${STRING##$PREFIX}
    SUBSTRING=${TEMP%%$SUFFIX}
    debug "SUBSTRING=$SUBSTRING"
}

function getFragmentPath () {
    # Function to find the path to the SystemD service file used to manage starting/stopping the service
    #   $1 - the name of the systemd object to find (e.g. kubelet.service or docker.socket)
    # If the item is not is not found, FRAGPATH length will be 0.  You'll need to handle this condition where
    # the function is called from.

    local TMP=$(systemctl show -p FragmentPath $1)

    debug "$TMP"

    # A simple AWK script to grab everything after the = sign
    local TMP2=$(echo $TMP | awk '
        BEGIN {
            FS="=";
        }
        {
            print $2
        }')

    if [ -n "$TMP2" ]; then
        FRAGPATH=$TMP2
    else
        debug "FragmentPath $1 not found"
        comment "FragmentPath $1 not found"
        FRAGPATH=""
    fi

    debug "$1 FragmentPath: $FRAGPATH"
}

function System {
    header "System_BIOS" "Background"
        comment "Collect BIOS information for review and comparison against known CVEs.  BIOS vulnerabilities are particularly nasty in that they can affect an OS before it fully boots."
        comment "They are also, thankfully, rarer than your garden-variety CVE affecting general-purpose software components." 
        dumpcmd "dmidecode -t bios"
    footer

    header "System_BootLoaderInfo" "1.4.1"
        comment "This probably isn't useful in audits where the server is a virtual machine on a cloud provider's IaaS or even on a private VMWare stack.  Still it's there if you need it."
        dumpfile "/boot" "*.cfg" "2"
    footer

    header "System_CrontabConfig" "Background"
        comment "Cron is the task scheduler, so you can use this to get a list of (and even the contents of) the scheduled tasks running on a system.  E.g. backup jobs on database servers."
        comment "Also take a look at System_Timers below as this is the SystemD method of scheduling jobs"
        dumpcmd "crontab -l"
        dumpfile /etc "crontab"
        if [ -e /etc/cron.allow ]; then 
            comment "Cron.allow exists.  Only listed users are permitted to modify cron jobs.  If cron.allow is blank,"
            comment "then only ROOT is permitted to modify cron jobs."
            comment "File contents: /etc/cron.allow"
            dumpfile "/etc" "cron.allow"
        else
            comment "Cron.allow does not exist.  Users listed in cron.deny are denied access to modify cron jobs.  All other"
            comment "users are permitted access."
            comment "File contents: /etc/cron.deny"
            dumpfile "/etc" "cron.deny"
        fi
        dumpfile "/etc/cron.d" "*"
        dumpfile "/etc/cron.daily" "*"
        dumpfile "/etc/cron.weekly" "*"
        dumpfile "/etc/cron.monthly" "*"
    footer

    header "System_UserCrontab" "Background"
        comment "Per-user crontabs (if any) are created in /var/spool/cron (or /var/spool/cron/crontabs for Debian-based systems)"
        #Capture all per-user crontabs, including in one level of sub-directories
        dumpfile "/var/spool/cron" "*" "2"
    footer

    header "System_Timers" "Background"
        comment "SystemD can also user 'timers' in addition to jobs listed in the 'System_CrontabConfig' section above.  This is a list of the scheduled timers and their configurations"
        dumpcmd "systemctl --full --timestamp=utc list-timers"
        for ITEM in $(systemctl list-unit-files --type=timer --state=enabled --state=static | awk '/timer/{ print $1 } '); do 
            SECTION="System_Timers-$ITEM"
            dumpcmd "systemctl cat $ITEM"
        done
        SECTION="System_Timers"
    footer

    header "System_FSEncryption" "Background"
        comment "File system encryption can be implemented at various points in the stack, including by the OS itself.  We grab these configs if Linux itself is doing the encryption."
        # Print the "cryptsetup status" output for each encrypted volume listed in /dev/mapper

        # Count the number of entries in /dev/mapper (exclude "control")
        MAPPERCOUNT=$(ls -1 /dev/mapper | grep -v "control" | wc -l)

        debug "/etc/crypttab line count: $MAPPERCOUNT"

        # If there are any entries in /dev/mapper, print the status of each
        if [ $MAPPERCOUNT -gt 0 ]; then
            dumpfile "/etc" "crypttab"
            for n in $(ls -1 /dev/mapper | grep -v "control"); do
                SECTION="System_FSEncryption-$n"
                debug "crypttab setup $n"
                dumpcmd "cryptsetup status $n"
            done
        else
            comment "No encrypted volumes found in /dev/mapper"
        fi

        SECTION="System_FSEncryption"
    footer

    header "System_FSMounts" "1.1.2 through 1.1.20"
        comment "This will collect a list of all file system mounts.  Sometimes, for instance, the backups are written to a remote NFS server.  In this case, the mount point will be listed here."
        SECTION='System_FSMounts-mounts'
            dumpcmd "mount"
        SECTION='System_FSMounts-fstab'
            dumpfile "/etc" "fstab"
        SECTION='System_FSMounts-systemctl'
            dumpcmd "systemctl list-units --all --type=mount"
        SECTION='System_FSMounts'
    footer

    header "System_FSModules" "1.1.1.x"
        comment "This is a straight-up CIS benchmark check for which file system modules are supported by the server.  Some of these might be required in specific situationsn -- such as Docker."
        comment "But if those conditions aren't present, then this is indicative that CIS guidelines might not be strictly followed."
        
        #Setup an array of file system modules that we'll loop through below
        ITEMS=(cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat)

        #Loop through each of these file system modules (separated by newlines)
        for ITEM in ${ITEMS[*]}; do 
            #Reset "Supported" to 0 at each pass in the loop
            SUPPORTED=0
            #Make a dry run on inserting the file system module - this will not actually insert anything
            #Capture the text results in MODPROBE and discard any error messages
            MODPROBE=$(modprobe -n -v $ITEM 2>/dev/null)
            #Check if $MODPROBE returned any results (string length > 0)
            if [ -n "$MODPROBE" ]; then
                #Check if modprobe "succeded" because of an override in modprobe.d
                echo $MODPROBE | grep -i "install /bin/true" >/dev/null
                if [ $? = 1 ]; then
                    SUPPORTED=1
                fi
            else
                #Check if the module is already installed into the kernel
                lsmod | grep $n
                if [ $? = 0 ]; then
                    SUPPORTED=1
                fi
            fi
            #Report the results
            if [ $SUPPORTED -eq 1 ]; then 
                echo -e "$SECTION:: $ITEM file system is supported" >> $REPORT_NAME
            else
                echo -e "$SECTION:: $ITEM file system is NOT supported" >> $REPORT_NAME
            fi
        done
    footer

    header "System_InittabInfo" "Background"
        comment "Old-style System V initializatin system configuration file.  Might not be in use.  See https://geek-university.com/linux/etc-inittab/ for more info."
        dumpfile "/etc" "inittab"
    footer

    header "System_KernelSysctlConf" "Background"
        comment "This section collects the CONFIGURED status for various kernel parameters -- in other words, how the system will start-up the next time it's rebooted."
        comment "Most of these details are probably not useful in most audits, but they're here if you need them."
        dumpfile "/etc" "sysctl.conf"
        dumpfile "/etc/sysctl.d" "*"
        dumpfile "/usr/lib/sysctl.d" "*"
        dumpfile "/run/sysctl.d" "*"
    footer

    header "System_KernelSysctlRunningConfig" "Background"
        comment "This section collects the RUNNING status for various kernel parameters.  Most of these details are probably not useful in most audits, but they're here if you need them."
        comment "NOTE: If there's discrepency between a CONFIGURED (System_KernelSysctlConf) item and a RUNNING item in this section, that could be interesting."
        dumpcmd "sysctl -a"
    footer

    header "System_LoginBanners" "1.7.1.x"
        comment "Various login banners that could be displayed for users on logging in."
        ITEMS=(motd issue issue.net)
        for ITEM in ${ITEMS[*]}; do 
            comment "/etc/$ITEM Permissions and ownership"
                dumpcmd "stat /etc/$n"
            comment "/etc/$ITEM Contents:"
                dumpfile "/etc" "$ITEM"
        done
    footer

    header "System_MACIntro" "1.6.1.1"
        comment "SELinux and AppArmor both implement enahnced security on Linux by introducing Mandatory Access Controls (MACs)"
        comment "to the Linux kernel.  This can, among other benefits, be used to enforce inter-process behavior beyond just the" 
        comment "user security model we're already accustomed to.  For CIS 1.6.1.1, you should find that either SELinux or AppArmor"
        comment "is installed, as reported in the followint two checks."
    footer

    header "System_MACAppArmorInfo" "1.6.1.1"
        dumpcmd "apparmor_status"
    footer

    header "System_MACSELinuxInfo" "1.6.1.1"
        dumpcmd "sestatus"
    footer

    header "System_MemoryASLRConfig" "1.5.3"
        comment "ASLR provides security enhancement by randomizing memory locations, making it harder for hackers to execute"
        comment "buffer overflow, stack overflow and other similar attacks.  Possible values:"
        comment "  0 = Disabled (bad)"
        comment "  1 = Enabled (OK)"
        comment "  2 = Enabled for data segments too (Best, and default for most modern systems)"
        dumpcmd "sysctl kernel.randomize_va_space" 
    footer

    header "System_MemoryCoreDump" "1.5.1"
        comment "A value of 0 indicates that SUID programs will not dump core (desired).  SUID programs run with elevated"
        comment "permissions and core dumps could contain sensitive system information."
        dumpcmd "sysctl fs.suid_dumpable"
    footer

    header "System_PackageInstalledSoftware" "Background"
        comment "This section collects a list of installed packages as well patching update history (distribution-dependent)."
        SECTION="System_PackageInstalledSoftware-rpm"
        comment "RPM installed packages (common for Redhat-based systems)"
            dumpcmd "rpm -qa --last"
        SECTION="System_PackageInstalledSoftware-dnf"
        comment "dnf history results"
            dumpcmd "dnf history list"
        SECTION="System_PackageInstalledSoftware-dpkg"
        comment "DPKG is the package manager for Debian-based systems.  First we'll dump the status of all of the packages on the system"
            dumpcmd "dpkg --get-selections"
        comment "Apt keeps a history of commands in /var/log/apt/history.log, so we'll grab that too."
            dumpfile "/var/log/apt" "history.log"
        comment "dpkg keeps a log of its activity in /var/log/dpkg.log, which is subject to LogRotate.  We'll grab the install"
        comment "activity for as far as logrotate keeps it on the local system. To see how LogRotate is configured for these logs, "
        comment "see the section Logging__SyslogLogrotateConfig"
        comment "To make sense of some of what you're seeing in these logs, try out this link: https://linuxhint.com/see-dpkg-apt-history/"
            dumpgrep "status \(install\|update\)" "/var/log" "dpkg.log*"
    footer

    header "System_PackageManagerConfigs" "1.2.1 1.2.2 1.2.3"
        comment "This section provides the configuration that the package manager is using, which includes trusted sources.  Might be useful if you start tracking down patching issues."
        comment "Repo configurations"
            dumpfile "/etc" "yum.conf"
            dumpfile "/etc/yum.repos.d" "*"
            dumpfile "/etc/dnf" "*.conf"
            dumpfile "/etc/apt" "sources.list"
            dumpfile "/etc/apt/apt.conf.d" "*"
        comment "GPG configurations"
            dumpcmd "rpm -qa --scripts  gpg-pubkey* --qf '%{Version}-%{Release}  %{Packager}\n'"
            dumpcmd "grep ^gpgcheck /etc/yum.conf /etc/yum.repos.d/*"
            dumpcmd "apt-key list"
    footer

    header "System_PackageManagerUpdates" "1.8"
        comment "This section is really important for auditing patching cadence and missing critical security vulnerability patches.  We use the operating system's own tools to query"
        comment "to compare available updates against currently-installed software versions.  Use this section to determine the criticality of any missing updates."
        comment "Use the System_PackageInstalledSoftware section to determine patching cadence."
        echo -e "[*] Enumerating any missing package manager updates, which could take a while.\n[*] Please wait..."
        SECTION="System_PackageManagerUpdates-dnf"
        comment "Prefer DNF updates for RPM-based devices, if supported on this system"
            dumpcmd "dnf list updates"
        SECTION="System_PackageManagerUpdates-yum"
        comment "Use YUM results in case dnf didn't work"
            dumpcmd "yum list updates"
        SECTION="System_PackageManagerUpdates-apt"
        comment "Apt package updates"
            # The following commands will update the "apt" package database and then simulate an update.  The "assume-no" is the 
            # same as responding "No" to the "Do you want to continue" prompt. No updates will be applied to the system.
            dumpcmd "apt-get update"
            comment "Use apt-get to check for available package updates"
                dumpcmd "apt-get -V -u upgrade --assume-no"
            comment "Check Ubuntu supported package status"
                dumpcmd "ubuntu-support-status --show-unsupported"
    footer

    header "System_Snaps" "Background"
        comment "Snaps are another method of installing software -- especially popular on Ubuntu-based systems."
        comment "You probably won't see them too much on a server, but we collect the installed snaps just in case."
            dumpcmd "snap list"
    footer

    header "System_RunningProcesses" "Background"
        comment "This is as good as a blood test at the doctor's office.  If it's not listed here, the process isn't running. You can use it to find running anti-virus daemons, database"
        comment "servers, Docker containers and just about anything else."
        dumpcmd "ps -eaux"
    footer
}

function Network {
    header "Network_ConnectivityTest" "Background"
        comment "A quick PING test to google.com.  On a PCI audit, ideally this would fail from systems in the CDE (not necessarily those that are \"connected to\")."
        comment "If it doesn't, it's worth a conversation as all inbound and outbound communication must be explicitly defined for the CDE."
        comment "If it's not a PCI audit, you can decide if this is helpful to you."
        comment "Pinging www.google.com"
            dumpcmd "ping -c4 www.google.com"
    footer

    header "Network_DNSResolver" "Background"
        comment "We collect the DNS resolver configuration.  Using an external resolver (e.g. 8.8.8.8 for Google) could open up some interesting attack vectors through DNS poisoning."
        comment "It's also interesting to note if there are any differences across the sample population as differences could be indicative of systems under differing levels of management."
        dumpfile "/etc" "resolv.conf"
    footer

    header "Network_FirewallIntro" "3.5"
        comment "FirewallD, IPTables and UFW are user-space front ends to the Linux 'netfilter' kernel module."
        comment "If they are all installed IPTables, UFW and FirewallD may all display similar or even identical information."
    footer

    header "Network_FirewallFirewallD" "3.5"
        dumpcmd "firewall-cmd --list-all"
    footer

    header "Network_FirewallIPTables" "3.5"
        comment "IPTables uses several different tables to achieve different effects on network traffic passing through it."
        comment "We will grab the FILTER, NAT and MANGLE tables.  Review the man page for iptables or online documentation for more info."
        
        #Setup an array of IPTables tables that we'll loop through to grab all of the rules
        TABLES=( filter nat mangle )

        for t in "${TABLES[@]}"; do
            SECTION="Network_FirewallIPTables$t"
            dumpcmd "iptables -t $t -L -n -v"
        done
    footer

    header "Network_FirewallUFW" "3.5"
        dumpcmd "ufw status verbose"
    footer

    header "Network_HostsAllowDeny" "3.3.2 3.3.3"
        comment "Hosts.allow and hosts.deny provide a very simple and - by modern standards - inadequate network access control"
        comment "method based on 'tcp_wrappers.'  They are only effective against network services that rely on 'tcp_wrappers' or"
        comment "that have been started by a tcp_wrappers-enabled xinetd server, both of which are becoming less popular."
        comment "Consider using netfilter-based firewall rules instead -- e.g. iptables, firewalld or ufw."

        dumpfile "/etc" "hosts.*"
    footer

    header "Network_ICMPRedirect" "3.1.2"
        comment "Unless the device is functioning as a router/firewall, these values should be 0.  \"send_redirects\" refers to sending ICMP Redirects."
        comment "This occurs when two routers exist on the same VLAN and R1 wants to tell the end-node to use R2 instead.  This also opens up some interesting network-layer attack vectors."
        comment "Refer to https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/nx-os-software/213841-understanding-icmp-redirect-messages.html for more info."
        dumpcmd "sysctl net.ipv4.conf.all.send_redirects"
        dumpcmd "sysctl net.ipv4.conf.default.send_redirects"
    footer

    header "Network_InterfacesIfConfig" "Background"
        comment "We collect the IP address information in case it's useful.  Different systems use different methods, so we try a few ways."
        dumpcmd "ifconfig -a"
    footer

    header "Network_InterfacesIPAddress" "Background"
        comment "We collect the IP address information in case it's useful.  Different systems use different methods, so we try a few ways."
        dumpcmd "ip address"
    footer

    header "Network_IPForwarding" "3.1.1"
        comment "Unless the device is functioning as a router/firewall, these values should be 0."
        comment "They might also be enabled if the device is a Docker host"
        dumpcmd "sysctl net.ipv4.ip_forward"
        dumpcmd "sysctl net.ipv6.conf.all.forwarding"
    footer

    header "Network_ListeningServices" "Background"
        comment "We list all of the listening ports, including the binary that's listening on it.  I consider \"System_RunningProcesses\", \"System_PackageManagerUpdates\","
        comment "and this section to be three most-valuable sections in the report."
        comment "Listening Network Ports"

        SECTION="Network_ListeningServicesNetstat"
            dumpcmd "netstat -lptun"
        SECTION="Network_ListeningServicesSS"
            dumpcmd "ss -lptun"
        SECTION="Network_ListeningServicesSockstat"
            comment "Listening Sockets"
            dumpcmd "sockstat -l"
    footer

    header "Network_NSSwitchConfig" "Background"
        comment "The Name Service Switch is involved in requests for nearly anything that needs to be looked up: host names, DNS names, service ports, users, groups, network protocols, etc"
        comment "The NSS is responsible for receiving requests from various applications and services and for passing those requests to the appropriate, system administrator-defined source."
        comment "For instance, by default, a request from a web browser for a URL will first be passed to the /etc/hosts file and then to DNS."
        dumpfile "/etc" "nsswitch.conf"
    footer
    
    header "Network_OpenSSHPermissions" "5.2.1 5.2.2 5.2.3"
        dumpcmd "stat /etc/ssh/sshd_config /etc/ssh/*_key /etc/ssh/*.pub"
    footer

    header "Network_OpenSSHServerConfig" "5.2.4 through 5.2.23"
        comment "These two methods will show similar information.  The first group will show the effect of the current configuration"
        comment "including the various defaults as applied.  The second method provides the entire sshd_config file, including"
        comment "comments, overridden values, etc."
        comment "OpenSSH effective configuration"
            dumpcmd "sshd -T"
        comment "OpenSSH /etc/sshd_config Contents:"
            dumpfile "/etc/ssh" "sshd_config"
            dumpfile "/etc/ssh/sshd_config.d" "*"
    footer

    header "Network_OpenSSHClientConfig" "5.2.4 through 5.2.23"
        comment "The site-wide client SSH configurations are used when an SSH sessions is initiated from this systems -- e.g. if this server is jumpbox used to connect to other systems."
        comment "NOTE: Users may also have a ~/.ssh/ssh_config file which might override some of these settings."
            dumpfile "/etc/ssh" "ssh_config"
            dumpfile "/etc/ssh/ssh_config.d" "*"
    footer

    header "Network_OpenSSHModuli" "5.2.4 through 5.2.23"
        comment "The /etc/ssh/moduli file contains the moduli used by the SSH server, especially when the key exchange"
        comment "details are not explicitly negotiated such as when diffie-hellman-group-exchange-sha256 is enabled in"
        comment "/etc/ssh/sshd_config.  We redact the modulus from the results."
        redactfile "/etc/ssh/moduli" "[A-Z0-9]{5,}$" "<MODULUS REDACTED>"
    footer

    header "Network_RouteTable" "Background"
        comment "This is probably only useful if you end up having to chase down something wonky in the network routing table.  But, we collect it just in case you might need it."
        dumpcmd "netstat -r"
        dumpcmd "ip route"
    footer

    header "Network_ServiceInfo" "2.x"
        comment "This section attempts to get the status of all of the running services on a system.  As various distros vary (and sometimes widely) on how they manage this, we try several different ways."
        comment "Some of them will provide duplicate information and none of them will probably work on any one distro.  Use this section to confirm if certain services are installed, enabled, disabled or running."
        SECTION="Network_ServiceInfo-systemctl"
            dumpcmd "systemctl list-unit-files"
        SECTION="Network_ServiceInfo-chkconfig"
            dumpcmd "chkconfig --list"
        SECTION="Network_ServiceInfo-initctl"
            dumpcmd "initctl list"
        SECTION="Network_ServiceInfo"
            dumpcmd "service -e"
            dumpcmd "service --status-all"
        SECTION="Network_ServiceInfo-launchctl"
            dumpcmd "launchctl list"
        SECTION="Network_ServiceInfo-svcs"
            dumpcmd "svcs 2> /dev/null"
        SECTION="Network_ServiceInfo"        
    footer

    header "Network_SharesNFS" "2.2.7"
        comment "These configurations drive whether or not this server is providing network file sharing services."
        comment "The Network File System (NFS) is common in Unix/Linux-only environments where SMB compatability is not needed for access to/from Windows systems"
        comment "nfs-server is the name of the service on Ubuntu.  For Redhat, it's just nfs.  In both cases, there are additional support services.  We'll list the status of all nfs-related services."
            for ITEM in $(systemctl list-unit-files | grep "nfs.*service" | awk '{print $1}'); 
                do svcstatus $ITEM
            done
            svcstatus "rpcbind"

        comment "NFS Server Configurations"
        dumpfile "/etc/default" "nfs-*"
        dumpfile "/etc" "nfs.conf"
        dumpfile "/etc/nfs.conf.d" "*.conf"

        comment "/etc/exports -- File systems/directories exported as NFS mount points that other systems can connect to.  https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/5/html/deployment_guide/s1-nfs-server-config-exports"
            dumpfile "/etc" "exports"
            dumpfile "/etc/exports.d" "*"
    footer
    
    header "Network_SharesSamba" "2.2.12"
        comment "Check if the SMB service is running. Samba provides Server Message Block file share compatibility so that the server can participate in Windows-based network file sharing"
            svcstatus "smbd"
        comment "/etc/smb.conf -- Configuration file for SAMBA that makes a Linux server behave like a Windows-based file server.  https://wiki.samba.org/index.php/Main_Page"
            dumpfile "/etc" "smb.conf" "2"
        comment "/etc/dfs -- Configuration for a Linux server to participate in a Windows DFS.  https://en.wikipedia.org/wiki/Distributed_File_System_(Microsoft)"
            dumpfile "/etc/dfs" "dfstab"
            dumpfile "/etc/dfs" "sharetab"
    footer

    header "Network_EtcHosts" "Background"
        comment "/etc/hosts -- local name-to-IP mapping.  Entries in this file generally tend to override DNS lookup (see Network__NSSwitchConfig section above to see if this has been overridden)."
            dumpfile "/etc" "hosts" "2"
    footer

    header "Network_SNMPInfo" "2.2.14"
        comment "We collect the SNMP configuration.  Of particular interest here is the permissions granted to each community strings -- could be read-only or read-write."
        comment "Read-write should be used sparingly if at all.  Even read-only can be interesting if it's using SNMPv2 -- which can't do encryption -- or SNMPv3 without crypto."
        dumpcmd "chkconfig --list snmpd"
        svcstatus "snmpd"
        dumpfile "/etc" "snmpd.conf" "2"
    footer

    header "Network_NTP" "2.2.1"
        comment "NTP services could be provided by several different daemons including ntpd, xntpd, chrony or timesyncd."
        comment "The following will check for each of them and display their configurations if available."
        comment "This section is really important to PCI audits for requirement 10.4.  Even outside of a PCI audit, differences between systems can be telling of an underlying configuration or log management issue."
        comment "See https://prog.world/linux-time-synchronization-ntp-chrony-and-systemd-timesyncd/ for a write-up on the popular NTP services."
        
        #Setup an array of NTP-ish config files that we can loop through 
        ITEMS=(ntp.conf xntp.conf chrony.conf timesyncd.conf)

        for ITEM in ${ITEMS[*]}; do
            dumpfile "/etc" "$ITEM" "3"
        done

        dumpfile "/etc/timesync.conf.d" "*"

        comment "Query the NTP server status."
            SECTION="Network_NTP-ntpd"
                dumpcmd "ntpq -p -c ntpversion"
            SECTION="Network_NTP-chronyd"
                dumpcmd "chronyc ntpdata"
            SECTION="Network_NTP-timesyncd"
                dumpcmd "timedatectl status"
                dumpcmd "timedatectl timesync-status"
                dumpcmd "timedatectl show-timesync"
    footer

    header "Network_WebserverApacheHTTPDConfig" "2.2.10"
        comment "We try to grab the relevant files for the Apache web server configuration.  If they're using it, this section will provide web server host configurations such as the directory"
        comment "for web site content and the port that the site listens on.  You can also see HTTPS configuration settings here too."
        comment "See https://httpd.apache.org/docs/2.4/misc/security_tips.html for Apache's own tips for securing HTTPD (and there's a CIS Benchmark too)"
        dumpfile "/etc" "httpd.conf" "3"
        dumpfile "/etc" "apache2.conf" "3"
        dumpfile "/etc/apache2/sites-available" "*.conf"
    footer

    header "Network_WebserverApacheModSecurityInfo" "Background"
        comment "Mod_security is a commonly-used security module in Apache.  It might be the answer to \"Do you use a WAF?\""
        comment "See https://nature.berkeley.edu/~casterln/modsecurity/modsecurity2-apache-reference.html for the official documentation."
        dumpfile "/etc" "modsecurity.conf" "3"
    footer

    header "Network_WebserverNginxConfig" "2.2.10"
        comment "nginx (\"Engine X\") is another popular web server, so we'll grab the config files here."
        comment "The files usually in the \"conf.d\" directory are used to set up the sites that the web server will provide."
        comment "See https://docs.nginx.com/nginx/admin-guide/security-controls/ for documetnation on nginx security."
        dumpfile "/etc" "nginx.conf" "2"
        dumpfile "/etc/nginx/conf.d" "*"
        dumpfile "/etc/nginx/sites-enabled" "*"
        dumpfile "/etc/nginx/sites-available" "*"
        dumpfile "/usr/local/nginx/conf" "nginx.conf"
        dumpfile "/usr/local/etc" "nginx.conf" "2"
        dumpfile "/usr/local/etc/conf.d" "*"
    footer
}

function Security {
    header "Security_AVClamAVInfo" "Background"
        comment "The ubiquitious ClamAV for Linux.  Far from the best, but still we collect the configs in case that's the answer for \"Linux AV\"."
        comment "FreshClam is the process that checks for AV signature updates."
            dumpfile "/etc/" "freshclam.conf"
            dumpfile "/etc/clam.d" "*.conf"
            dumpfile "/etc/clamav" "*.conf"
    footer

    header "Security_HidsAIDEConfig" "1.3.1 1.3.2"
        comment "AIDE is free replacement for Tripwire.  It is a file integrity monitoring solution available on most Linux"
        comment "distributions where that function used to be provided by a free version of Tripwire."
        dumpcmd "rpm -q aide"
        dumpcmd "dpkg -s aide"
        dumpcmd "aide -v"
        #Grab all files under /etc/aide/*/* (one additional sub directory).  This will ensure that we get all of the per-directory/per-service/per-xxx configs
        dumpfile "/etc/aide" "*" "2"
    footer

    header "Security_HidsCarbonBlack" "Background"
        comment "CarbonBlack is an increasinbly-popular Endpoint Detection and Response.  It's much more than AV, even though that's frequently where we first hear of it in a customer's environment."
        comment "It might also be the answer for FIM and a few other things."
        # Look for .conf files under /etc/cb and 2 additional levels
        dumpfile "/etc/cb" "*.conf" "3"
        dumpfile "/var/lib/cb" "sensorsettings.ini"
        dumpcmd "ps -f -C cbagentd"
    footer

    header "Security_HidsCrowdStrike" "Background"
        comment "CrowdStrike is a cloud-based HIDS agent from CrowdStrike.com.  The only check is to see that the service is running"
        svcstatus "falcon-sensor"
        dumpcmd "ps -f -C falcon"
    footer

    header "Security_HidsOSSECConfig" "Background"
        comment "The ossec.conf file is valid for both the OSSEC agent and the Wuzah agent"
        dumpfile "/var/ossec/etc" "ossec.conf"
        #Look for "ossec.conf" in /etc and in first-level sub-directories (e.g. /etc/ossec/ossec.conf but not /etc/xxx/yyy/ossec.conf)
        dumpfile "/etc" "ossec.conf" "2"
    footer

    header "Security_HidsTripwireConfig" "1.3.1 1.3.2"
        dumpcmd "twadmin --print-cfgfile"
        #Look for "tw*.txt" in /etc and in first-level sub-directories (e.g. /etc/tripwire/tw.txt but not /etc/xxx/yyy/tw.txt)
        dumpfile "/etc" "tw*.txt" "2"
    footer

    header "Security_IPSecConfig" "Background"
        comment "The Linux kernel supports IPSec connections, so we'll grab the configurations if it's enabled.  Check out our Confluence page for auditing Ciphersuites at:"
        comment "https://kirkpatrickprice.atlassian.net/l/c/4121Zw4B"
        # Obtain the stats (esepcially permissions) on the IPSec configuration files
        for n in $(find /etc -iname "ipsec.conf" -o -iname "ipsec.secrets"); do
            dumpcmd "stat $n"
        done
        # Dump only the ipsec.conf file (do not dump ipsec.secrets)
        dumpfile "/etc/" "ipsec.conf"
    footer

    header "Security_IPSecStatus" "Background"
        comment "'ipsec statusall' is used for StrongSwan"
            dumpcmd "ipsec statusall"
        comment "'ipsec auto status' is used for LibreSwan"
            dumpcmd "ipsec auto status"
    footer

    header "Security_NIDSSnortConfig" "Background"
        comment "Snort used to be all the rage as a Network IDS back when data centers had everything.  It's use has dwindled, but we grab the configu if it's being used."
        dumpfile "/etc" "snort.conf"
    footer

    header "Security_OpenLDAPConfig" "Background"
        comment "OpenLDAP is a directory server for Linux servers.  If being used, it's probably the central source of identity for all production Linux servers."
        comment "We're only grabbing the config file, so other checks such as password policy and group memberships will need to done elsewhere."
        dumpfile "/etc/openldap" "*.conf"
    footer

    header "Security_OpenVPNConfig" "Background"
        comment "OpenVPN might be the answer for remote access VPNs for administrator access, or it might be used in a site-to-site (Layer 3) VPN similar to IPSec."
        comment "It's based on TLS technology, so audit the crypto-config like you would any other TLS implementation.  See https://kirkpatrickprice.atlassian.net/l/c/F6Zh6gi3 for some guidance."
        svcstatus "openvpn"
        dumpcmd "openvpn --version"
        comment "OpenVPN can be configured in either/both SERVER and CLIENT mode.  Look for both configurations under /etc/openvpn."
            #Look in /etc/openvpn plus two additional directories below that (e.g. /etc/openvpn/server/dir1) for any *.conf files
            dumpfile "/etc/openvpn" "*.conf" "3"
        comment "EasyRSA is also released by the OpenVPN project and is a common -- and very easy -- certificate authority that is"
        comment "a popular pairing with standalone OpenVPN installations.  It can be configured in a numnber of ways, and we're"
        comment "making some assumptions here:"
        comment "   1) Start with pki directories in /etc -- if any config files are found, this is probably the one you need."
        comment "      On a fresh Ubuntu machine using the Apt package, this is /etc/pki."
        comment "      On a fresh Amazon Linux 2 or CentOS machine using the Yum package, this is /etc/openldap/certs/pki"
        comment "   2) Look for directies with 'easy-rsa' in the name. These are *usually* templates, so prefer /etc files instead."
        comment "If a different CA is being used, you'll need to review the configuration separately."
        #Loop through all "pki" directories under /etc to find our EasyRSA root folder and then dump any "cnf" files we find.  
        #On a fresh Ubuntu machine using the Apt package, this is /etc/pki.  
        #On a fresh Amazon Linux 2 or CentOS machine using the Yum package, this is /etc/openldap/certs/pki
        for n in $(find /etc -type d -iname pki); do
            dumpfile "$n" "*.cnf"
        done

        dumpfile "/etc/pki" "*.cnf"
        #Loop through all directories that include "easy-rsa" in the name and dump any ".cnf" files found
        for n in $(find /etc /usr /var -type d -iname easy-rsa); do
            dumpfile "$n" "*.cnf" "3"
            dumpfile "$n" "vars*" "3"
        done
    footer
}

function Logging {
    header "Logging_AuditdStatus" "Background"
        comment "AuditD performs kernel-level logging.  It can generate a lot of data and requires special tools to make the most sense out of the output, so we only grab the configs and none of the events."
        comment "Some CIS benchmarks for both Linux and Docker (and probably others) are based on AuditD, so we also check to see if it's running at all."
        svcstatus "auditd"
    footer
    
    header "Logging_AuditdConfig" "4.1"
        comment "This section provides the SAVED auditd configuration -- the one that will be used when the server reboots."
        dumpfile "/etc/audit" "*"    
    footer

    header "Logging_AuditdRunningConfig" "4.1"
        comment "This section provides the RUNNING auditd configuraion -- the one that was in force when the script was run.  Differences between this and the SAVED configuration could be interesting."
        dumpcmd "auditctl -l"
    footer

    header "Logging_AuditdSETUID" "4.1.13"
        comment "Check that usage of all SETUID binaries (those that will run as a fixed, usually elevated, user) is logged.  This is a specific CIS benchmark check.  See below for how to make sense of this output."
        comment "Output:"
        comment "   <path-to-binary> <number-of-auditd-matches>"
        comment "   A 0 following the file indicates it is not being monitored by auditd"
        
        # Check that auditctl is installed
        if [ -n "$(which auditctl 2> /dev/null)" ]; then
            for n in $(find /bin /opt /root /sbin /usr -xdev \( -perm -4000 -o -perm -2000 \) -type f); do
                echo -e "$SECTION:: $n\t\tAuditdRuleCount:$(auditctl -l 2> /dev/null | grep -c $n 2> /dev/null)" >> $REPORT_NAME 
            done
        else
            comment "auditctl command not installed.  Confirm that AuditD is installed."
        fi

    footer

    header "Logging_Datadog" "Background"
        comment "Datadog is a common log management solution we might see in use by our customers.  The agent is in use whenever the Datadog solution is in use."
        comment "We'll grab the contents of the /etc/datadog-agent/datadog.yaml file and the conf.d directory.  See"
        comment "https://docs.datadoghq.com/agent/guide/agent-configuration-files/?tab=agentv6v7 for information on how to read this file"

        dumpfile "/etc/datadog-agent" "*.yaml"
        #This should be a ridiculous MAXDEPTH=4, but without knowing just how deep the directory structure might be, I went for "too deep" rather than "not deep enough"
        dumpfile "/etc/datadog-agent/conf.d" "*" "4"
    footer

    header "Logging_FluentD" "Background"
        comment "FluentD is a common log harvester solution we might see in use by our customers.  We'll grab the contents of the"
        comment "/etc/fluent/fluent.conf file.  See https://docs.fluentd.org/configuration/config-file for information on how to read this file"

        dumpfile "/etc/fluent" "*.conf"
    footer

    header "Logging_SyslogIntro" "4.2.1"
        comment "Syslog, RSysLog and Syslog-ng all perform similar functions -- turn system and application messages into logs."
        comment "You should see one but probably not more than one of them listed below.  RSysLog is used on default Ubuntu and"
        comment "CentOS installations.  The others are collected here in the event local conditions have led to their use."
        comment "A common check here is to make sure that logs are shipped to an external, centralized log server.  OSSEC or another tool might also capture the logs, but if none of those"
        comment "are installed, then SysLog will need to do it.  Check for lines with an @ sign."
    footer

    header "Logging_SyslogRsyslogdConfig" "4.2.1"
        comment "Default logging facility for recent Ubuntu and CentOS installations"
        svcstatus "rsyslog"
        dumpfile "/etc" "rsyslog.conf"
        dumpfile "/etc/rsyslog.d" "*.conf"
    footer

    header "Logging_SyslogSyslogdConfig" "4.2.1"
        comment "Older logging facility that might still be in use."
        dumpfile "/etc" "syslog.conf"
    footer

    header "Logging_SyslogSyslogngConfig" "4.2.1"
        comment "A popular logging facility"
        svcstatus "syslog-ng"
        dumpfile "/etc" "syslog-ng.conf" "2"
    footer

    header "Logging_SyslogLogrotateConfig" "4.3"
        comment "LogRotate prunes the logs on the local disk so they don't fill up the drive.  If they're not shipped to another log server or SIEM tool by OSSEC, Syslog or something else"
        comment "then when LogRotate deletes the log, it's gone forever.  See https://www.redhat.com/sysadmin/setting-logrotate for more information on how to read these files."
        dumpfile "/etc" "logrotate.conf"
        dumpfile "/etc/logrotate.d" "*"
    footer

    header "Logging_LogFilePermissions"
        comment "Collect log file permissions for a few key log files"
        ITEMS=(messages secure boot.log auth.log audit/audit.log syslog apache2 httpd nginx/access.log)

        for ITEM in ${ITEMS[*]}; do
            dumpcmd "ls -l /var/log/$ITEM"
        done

    header "Logging_Samples" "Background"
        comment "A full list of the /var/log sub-directory.  Below, we grab samples of some of the common ones, but if any of these other log files look interesting, you'll need to request those separately"
        SECTION="Logging_SamplesVarLogList"
            dumpcmd "find /var/log"

        comment "We collect samples of various logs below.  To save space, we collect only the first and last 25 lines of each file to confirm that events were and continue to be written to the logs."
        comment "If you need to see more of some log files, you'll need to ask for those separately"
        
        #Setup an array of log files (under /var/log) that we'll loop through below
        ITEMS=(messages secure boot.log auth.log audit/audit.log syslog apache2 httpd nginx/access.log)

        #For each of the log files in the array, grab the first and last 25 lines from the file
        for ITEM in ${ITEMS[*]}; do
            SECTION="Logging_Samples-$ITEM-head"
            dumpcmd "head --lines=25 /var/log/$ITEM"
            SECTION="Logging_Samples-$ITEM-tail"
            dumpcmd "tail --lines=25 /var/log/$ITEM"
        done
        SECTION="Logging_Samples"
    footer
}

function Users {
    header "Users_SSSDConfig"
        comment "SSSD consists of a set of Linux authentication daemons that can be used to integrate with remote directory services (e.g. Active Directory) or other authencation systems."
        dumpfile "/etc" "sssd.conf" "3"
    footer
    
    header "Users_BlankPasswd" "Background"
        comment "This check identifies any users with a blank password.  This does not include users with a \"LOCKED\" password as those show up in /etc/shadow as either \"*\" or \"!\"."
        comment "These are truly user accounts with blank password."
        #dumpcmd "awk -F: '\(\$2 == \"\") {print}' /etc/shadow"

        BLANKS+=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
        debug "Blank password array: \"${BLANKS[@]}\""
        if [[ ${#BLANKS[0]} -gt 0 ]]; then
            debug "BlankPW > 0"
            for ITEM in ${BLANKS[@]}; do
                echo -e "$SECTION::User \"$ITEM\" has a blank password" >> $REPORT_NAME
            done
        else
            debug "BlankPW = 0"
            echo -e "$SECTION::No blank passwords found" >> $REPORT_NAME
        fi
    footer

    header "Users_DefaultSettings" "5.4.1"
        comment "See https://ostechnix.com/how-to-set-password-policies-in-linux/ for some guidance on"
        comment "testing password policies for various distros."
        comment "useradd -D defaults"
            dumpcmd "useradd -D"
        comment "Login.defs defaults"
            dumpfile "/etc" "login.defs"
            dumpfile "/etc/default" "useradd"
        comment "Password Quality for RPM-based systems.  Debian-based systems like"
        comment "Ubuntu will be captured in the Users_PAMConfig section further on."
            dumpfile "/etc/security" "pwquality.conf"
            dumpfile "/etc/security/pwquality.conf.d" "*"
    footer

    header "Users_etcpasswdContents" "5.4"
        comment "A list of all locally-defined users.  You can safely disregard any user with \"/bin/false\" or \"/sbin/nologin\" as they can't login.  But any user with \"/bin/bash\" is fair game."
        dumpfile "/etc" "passwd"
    footer

    header "Users_etcgroupContents" "5.4"
        comment "A list of groups and their memberships.  Of special interest:"
        comment "  sudo -- Users who can issue commands as root (default /etc/sudoers configuration)"
        comment "  adm -- Users who might be able to issue commands as root (check the /etc/sudoers configuration)"
        comment "  Any other group listed in the /etc/sudoers config listed in Users_SudoersConfig section"
        dumpfile "/etc" "group"
    footer

    header "Users_KerberosConfig" "Background"
        comment "Kerberos isn't used very often as a SSO platform for Linux, but we grab the config just in case you bump into it."
        dumpfile "/etc" "krb5.conf" "2"
        dumpfile "/etc/krb5.conf.d" "*"
    footer

    header "Users_LoginHistory" "Background"
        comment "This is a list of the last time each user has logged in.  It could be interesting if you see ROOT listed here with a recent date.  It usually means that ROOT can login through SSH,"
        comment "which could be indicative of generic/shared accounts (see PCI requirement 8.5)"
        dumpcmd "lastlog"
    footer

    header "Users_LastLog90" "Background"
        comment "This is a list of local (/etc/passwd) user IDs that have not logged in within the last 90 days"
        comment "You need this for a PCI audit, but it's also important for many other audits"
        dumpcmd "lastlog -b 90"
    footer

    header "Users_PAMConfig" "5.3"
        comment "An excellent source of PAM documentation is from the PAM project itself.  There are also reference guides available for each PAM module in the default set."
        comment "http://linux-pam.org/Linux-PAM-html/Linux-PAM_SAG.html"
        dumpfile "/etc" "pam.conf"
        dumpfile "/etc/pam.d" "*"
    footer

    header "Users_Profile" "5.4.4 5.4.5"
        comment "The Profile files in /etc and /etc/profile.d control defaults for user shells upon login.  The answers to"
        comment "a few CIS benchmark items can be found in these files, but they might also be useful for confirming other system-wide defaults."

        #/etc/bashrc might also /etc/bash.bashrc at least on Ubuntu 20.04.  We'll grab all variations so long it has bashrc in the filename
        dumpfile "/etc" "*bashrc*"
        dumpfile "/etc" "profile"
        dumpfile "/etc/profile.d" "*"
    footer

    header "Users_SudoersConfig" "Background"
        comment "The Sudoers config determines which users and groups can execute commands as ROOT by prefacing the command with \"sudo <command\"."
        comment "See https://xkcd.com/149/ for a visual reference of the effect that the SUDO command has and https://www.linux.com/training-tutorials/configuring-linux-sudoers-file/ for a more detailed explanation."
        dumpfile "/etc" "sudoers"
        dumpfile "/etc/sudoers.d" "*"
        dumpfile "/etc" "sudo.conf"
    footer

    header "Users_UserStatus" "5.4.1"
        comment "Provide the status of each user in /etc/passwd.  See https://man7.org/linux/man-pages/man1/passwd.1.html (check out the -S section about halfway down) for how to read this output."
        comment "SPECIAL NOTE: \"LOCKED\" only means they can't use a passowrd to login.  SSH key-based authentication will still work if the user has a \"~/.ssh/authorized_keys\" file (Users_AuthorizedKeys)."
        #Loop through users in /etc/passwd.  Using a for loop as not all common platforms support the "passwd -Sa" method
        for n in $(awk -F ":" '{print $1}' /etc/passwd); do
            dumpcmd "passwd -S $n"
        done
    footer

    header "Users_AuthorizedKeys" "Background"
        comment "The presence of a user's .ssh/authorized_keys file indicates the potential to login via SSH.  This would override the LOCKED status results of the Users_UserStatus check later in the script."
        dumpcmd "ls -1 /home/*/.ssh/authorized_keys"
    footer

    header "Users_SubuidSubgid"
        comment "/etc/subuid and /etc/subgid are useful especially if the host is a Docker host with user namespaces enabled.  Check the /etc/docker/daemon.json file to see if this is the case."
        comment "There might be other places where this is useful.  For instance, if the Running Process List section shows numbers in field one instead of names, you might be able to map them"
        comment "back to the real user using the /etc/subuid file.  Reference the man subuid help page for additional information"
        dumpfile "/etc" "subuid"
        dumpfile "/etc" "subgid"
    footer
}

function K8s {
    debug "Kube user config: $KUBEUSERCONFIG"
    debug "kubectl command line: $KUBECTL"

    header "K8s_Background" "Background"
        comment "The K8s section is broken down as follows:"
        comment "   Background -- contextual information on the state of the Kubernetes implementation is gathered.  This info"
        comment "       might be helpful in understanding how K8s is configured and used"
        comment "   CIS Benchmarks -- gather information necessary to check against the CIS Kubernetes Benchmark v1.6.0"
        comment "The script will attempt to determine if the server is a master or worker node based on the presence/absence"
        comment "of kube-apiserver (master) and kubelet (worker).  This can be overridden with the -m switch."

    header "K8s_Version" "Background"
        dumpcmd "$KUBECTL version"
    footer
}

function K8sMaster {

    K8s

    header "K8sMaster_Clusters" "Background"
        comment "Clusters consist of the worker and master nodes that work together to run pods."
        dumpcmd "$KUBECTL config get-clusters"

    header "K8sMaster_ClusterInfo" "Background"
        comment "Cluster-info provides some basic information about the cluster."
        dumpcmd "$KUBECTL cluster-info"
    footer

    header "K8sMaster_Nodes" "Background"
        comment "For more info on nodes, see https://kubernetes.io/docs/concepts/architecture/nodes/"
        comment "Nodes are servers running the resources necessary to participate in a Kubernets cluster.  This includes"
        comment "a container platform (usually Docker), kube-proxy (to manage networking) and kubelet (to interface with the control plane)"
        dumpcmd "$KUBECTL get nodes -o wide"
    footer

    header "K8sMaster_Namespaces" "Background 5.7.1"
        comment "For more info on namespaces, see https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/"
        comment "Not every installation will use them, so you might only see the default namespace and the ones used by kubes itself"
        dumpcmd "$KUBECTL describe namespaces"
    footer

    header "K8sMaster_Pods" "Background"
        comment "For more info on pods, see https://kubernetes.io/docs/concepts/workloads/pods/"
        comment "Pods are the basic units of work in Kubes.  It's a group of one or more containers that work together along with"
        comment "storage and network resources and a specification for how the container(s) should be run."
        dumpcmd "$KUBECTL get pods --all-namespaces -o wide"
    footer

    header "K8sMaster_Services" "Background"
        comment "For more info on services, see https://kubernetes.io/docs/concepts/services-networking/service/"
        comment "Services expose an application inside a pod (e.g. an NGinx web server) as a network service (e.g. tcp/80) to"
        comment "clients outside the cluster."
        dumpcmd "$KUBECTL get services --all-namespaces -o wide"
    footer

    header "K8sMaster_Deployments" "Background"
        comment "For more info on deployments, see https://kubernetes.io/docs/concepts/workloads/controllers/deployment"
        comment "Deployments provide a way to define the desired state (e.g. '4 copies of nginx') and then leave the details up to K8s."
        dumpcmd "$KUBECTL get deployments --all-namespaces -o wide"
    footer

    header "K8sMaster_PersistentVolumes" "Background"
        comment "For more info on volumes, see https://kubernetes.io/docs/concepts/storage/volumes/"
        comment "As storage within a container is not persistent (i.e. container contents are lost if it crashes), persistent data"
        comment "must be written to alternate storage, such as a directory on the host's file system or an NFS mount."
        dumpcmd "$KUBECTL get persistentvolumes --all-namespaces -o wide"
    footer

    header "K8sMaster_ConfigMaps" "Background"
        comment "For more info on ConfigMaps, see https://kubernetes.io/docs/concepts/configuration/configmap/"
        comment "ConfigMaps provide storage for name/value pairs that are used by the Kuberetes system and may also be used"
        comment "by pods."
        dumpcmd "$KUBECTL get configmaps --all-namespaces -o wide"
    footer

    header "K8sMaster_ReplicaSets" "Background"
        comment "For more info on ReplicaSets, see https://kubernetes.io/docs/concepts/workloads/controllers/replicaset/"
        comment "ReplicaSets are used to define the number of pods that should be running.  This is an important consideration for"
        comment "highly-available applications as K8s will ensure that pods are running on multiple nodes to ensure fault tolerance."
        comment "ReplicaSets might also be defined in Deployments above, and if so, these results will be similar to K8s_Deployments."
        dumpcmd "$KUBECTL get replicaset --all-namespaces -o wide"
    footer 

    header "K8sMaster_StatefulSets" "Background"
        comment "For more info on StatefulSets, see https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/"
        comment "StatefulSets are similar to Deployments and ReplicaSets, but are only used in situations where each pod in the set"
        comment "needs to be uniquely identifiable within the system.  This isn't very popular, but it's there anyway."
        dumpcmd "$KUBECTL get statefulsets --all-namespaces -o wide"
    footer

    header "K8sMaster_Jobs" "Background"
        comment "For more info on Jobs, see https://kubernetes.io/docs/concepts/workloads/controllers/job/"
        comment "Jobs start a pod to perform a specific task and then terminate the pod."
        dumpcmd "$KUBECTL get jobs --all-namespaces -o wide"
    footer

    header "K8sMaster_CronJobs" "Background"
        comment "For more info on CronJobs, see https://kubernetes.io/docs/concepts/workloads/controllers/cron-job/"
        comment "Cronjobs perform jobs on a schedule."
        dumpcmd "$KUBECTL get cronjobs --all-namespaces -o wide"
    footer

    header "K8sMaster_ManifestFiles" "1.1.1 through 1.1.10"
        for n in $(ls /etc/kubernetes/manifests); do 
            dumpcmd "stat /etc/kubernetes/manifests/$n"
        done
    footer

    header "K8sMaster_EtcdDataDir" "1.1.11 1.1.12"
        PROCESSNAME="etcd"
        CONFIGOPTION="data-dir"
        STRING=$(ps -f -C $PROCESSNAME | grep $CONFIGOPTION)

        debug "STRING: $STRING"

        #Get the text between "data-dir" and the next space -- it will be the path to etcd's data directory
        if [ -z "$STRING" ]; then
            comment "$SECTION:: $PROCESSNAME not running on this system"
        else
            getSubString "*$CONFIGOPTION=" " *"
            debug "ETC_DATA_DIR=$SUBSTRING"
            dumpcmd "stat $SUBSTRING"
        fi
    footer

    header "K8sMaster_AdminConf" "1.1.13 1.1.14"
        dumpcmd "stat /etc/kubernetes/admin.conf"
    footer

    header "K8sMaster_SchedulerConf" "1.1.15 1.1.16"
        dumpcmd "stat /etc/kubernetes/scheduler.conf"
    footer

    header "K8sMaster_ControllerConf" "1.1.17 1.1.18"
        dumpcmd "stat /etc/kubernetes/controller-manager.conf"
    footer

    header "K8sMaster_PKIDir" "1.1.19 through 1.1.21"
        dumpcmd "ls -laR /etc/kubernetes/pki"
    footer

    header "K8sMaster_ApiServerParams" "1.2.x 3.2"
        comment "Refer to the CIS benchmarks for all of the tests that can be accomplished by reviewing the kube-apiserver"
        comment "command line options.  Refer to Kubernetes documentation for default settings if not specified on the command line."

        dumpcmd "ps -f -C kube-apiserver"
        dumpfile "/etc/kubernetes/manifests" "kube-apiserver.yaml"
    footer

    header "K8sMaster_EncryptionConfig" "1.2.34"
        # Fist, we need to get the --encryption-provider-config file path, if it exists
        # Use a combination of ps and grep (with grep's EXITCODE) to determine if the API server was
        # started with this setting.  If not, report that crypto is not enabled.  Otherwise go deeper.

        CONFIGOPTION="encryption-prodvider-config"
        PROCESSNAME="kube-apiserver"
        STRING=$(ps -f -C $PROCESSNAME | grep $CONFIGOPTION)

        debug "STRING: $STRING"

        # Check if we got any results back, if not, report that the server wasn't started with the setting
        if [ -z "$STRING" ]; then
            comment "$SECTION:: $PROCESSNAME not started with $CONFIGOPTION"
        else
            #Get the text between "data-dir" and the next space -- it will be the path to etcd's data directory
            getSubString "*$CONFIGOPTION=" " *"
            debug "Encryption Config File=$SUBSTRING"
            redactfile "$SUBSTRING" "secret:.*" "secret:<REDACTED>"
        fi
    footer

    header "K8sMaster_ControllerParams" "1.3.x"
        comment "Refer to the CIS benchmarks for all of the tests that can be accomplished by reviewing the kube-controller-manager"
        comment "command line options.  Refer to Kubernetes documentation for default settings if not specified on the command line."

        dumpcmd "ps -f -C kube-controller-manager"
        dumpfile "/etc/kubernetes/manifests" "kube-controller-manager.yaml"
    footer

    header "K8sMaster_SchedulerParams" "1.4.x"
        comment "Refer to the CIS benchmarks for all of the tests that can be accomplished by reviewing the kube-scheduler"
        comment "command line options.  Refer to Kubernetes documentation for default settings if not specified on the command line."

        dumpcmd "ps -f -C kube-scheduler"
        dumpfile "/etc/kubernetes/manifests" "kube-scheduler.yaml"
    footer

    header "K8sMaster_EtcdParams" "2.x"
        comment "Refer to the CIS benchmarks for all of the tests that can be accomplished by reviewing the etcd service"
        comment "command line options.  Refer to Kubernetes documentation for default settings if not specified on the command line."

        # The following technique will return only the line that includes only etcd and will exclude the "grep" line 
        # that usually gets sucked in.
        dumpcmd "ps -f -C etcd"
        dumpfile "/etc/kubernetes/manifests" "etcd.yaml"
    footer

    header "K8sMaster_Users" "3.1"
        comment "Review the users list to determine their authentication method.  Compare to CIS Benchmarks for additional information."
        comment "Refer to Kubernetes documentation at https://kubernetes.io/docs/reference/access-authn-authz/authentication/."
        dumpcmd "$KUBECTL config view"
    footer

    header "K8sMaster_Logging" "3.2.x"
        # Check if the kube-apiserver was started with the --audit-policy-file option
        CONFIGOPTION="audit-policy-file"
        PROCESSNAME="kube-apiserver"
        STRING=$(ps -f -C $PROCESSNAME | grep $CONFIGOPTION)

        debug "STRING: $STRING"

        # Check if we got any results back, if not, report that the server wasn't started with the setting
        if [ -z "$STRING" ]; then
            comment "$SECTION:: $PROCESSNAME not started with $CONFIGOPTION"
        else
            #Get the text between "CONFIGOPTION" and the next space 
            getSubString "*$CONFIGOPTION=" " *"
            debug "Audit Policy File=$SUBSTRING"
            # We're not really redacting, we're just using redactfile because it's easier now that we have a full path
            redactfile "$AUDIT_POLICY_FILE" "randomtextthatwontexist" "randomtextthatwontexist"
        fi

    header "K8sMaster_ClusterRoles" "5.1.1"
        dumpcmd "$KUBECTL get clusterroles"
    footer
    
    header "K8sMaster_ClusterRoleBindings" "5.1.1"
        dumpcmd "$KUBECTL get clusterrolebindings -o=custom-columns=NAME:.metadata.name,ROLE:.roleRef.name,SUBJECT:.subjects[*].name"
    footer

    header "K8sMaster_PodSecurityPolicy" "5.2.x"
        comment "This command will provide the list of available pod security policies.  You may need to request" 
        comment "specific policies as a follow-up request."
        dumpcmd "$KUBECTL get psp --all-namespaces"
    footer

    header "K8sMaster_NetworkPolicies" "5.3.2"
        comment "For more info on Network Policies, see https://kubernetes.io/docs/concepts/services-networking/network-policies/"
        comment "Network policies define rules for ingress and egress traffic from pods, just like a firewall.  If no policies are"
        comment "defined, then the pod allows all communication and firewall rules will need to come from somewhere else."
        dumpcmd "$KUBECTL describe networkpolicies"
    footer

}

function K8sWorker {
    K8s

    header "K8sWorker_KubeletServiceFile" "4.1.1 4.1.2"
        comment "This check assumes systemd is used to manage system services and the default path to the Kubelet"
        comment "Service file"

        FRAGMENT="kubelet.service"

        getFragmentPath "$FRAGMENT" 
        
        if [ -n "$FRAGPATH" ]; then
        # If len(SERVICEPATH) > 0, stat the file
            dumpcmd "stat $FRAGPATH"
        else
        # otherwise, report that the service wasn't found
            comment "Service $FRAGMENT: NOTFOUND"
        fi
    footer

    header "K8sWorker_KubeProxyConfig" "4.1.3 4.1.4"
        PROCESSNAME="kube-proxy"
        CONFIGOPTION="config"
        STRING=$(ps -f -C $PROCESSNAME | grep $CONFIGOPTION)

        debug "STRING: $STRING"

        #Get the text between CONFIGOPTION and the next space
        if [ -z "$STRING" ]; then
            comment "$SECTION:: $PROCESSNAME not configured with $CONFIGOPTION.  It might be using ConfigMaps.  See CIS benchmark."
        else
            dumpcmd "ps -f -C $PROCESSNAME"
            getSubString "*$CONFIGOPTION=" " *"
            debug "kube-proxyconfig=$SUBSTRING"
            dumpcmd "stat $SUBSTRING"
            redactfile "$SUBSTRING" "textthatwontexist" "textthatwontexist"
        fi
    footer

    header "K8sWorker_KubeletKubeConfig" "4.1.5 4.1.6 4.2.x"
        comment "The configuration options specified in the CIS 4.2.x checks might be on the command line"
        comment "or in the kubelet config file.  Both are presented below."
        
        dumpcmd "ps -f -C kubelet"
        dumpcmd "stat /etc/kubernetes/kubelet.conf"
        redactfile "/etc/kubernetes/kubelet.conf" "(client|certificate)-.*-data:.*" "PKI Data has been REDACTED"
    footer

    header "K8sWorker_KubeletClientCA" "4.1.7 4.1.8"
        PROCESSNAME="kubelet"
        CONFIGOPTION="client-ca-file"
        STRING=$(ps -f -C $PROCESSNAME | grep $CONFIGOPTION)

        debug "STRING: $STRING"

        #Get the text between CONFIGOPTION and the next space
        if [ -z "$STRING" ]; then
            comment "$SECTION:: $PROCESSNAME not configured with $CONFIGOPTION."
        else
            getSubString "*$CONFIGOPTION=" " *"
            debug "kubeconfig=$SUBSTRING"
            dumpcmd "stat $SUBSTRING"
        fi
    footer
}

function Docker {

    header "Docker_Background" "Background"
        comment "Data collection for Docker is based on the CIS Docker Benchmark v1.2.0.  Most Level 1 items are included as"
        comment "well as some Level 2.  Docker can mean a lot of different things -- Docker Community Edition, Docker Enterprise"
        comment "Edition, Docker images and containiners performing workloads, the host where Docker runs, Docker Swarm, etc."
        comment "This script focuses on Docker CE and EE and where needed -- and not already covered by other modules --"
        comment "the Linux host running Docker.  Docker Swarm (functionality similar to Kubernetes) is not currently supported."
    footer

    header "Docker_Version" "1.1.2"
        dumpcmd "docker version"
    footer

    header "Docker_SystemInfo" "Background 2.4 2.5 2.12 2.13 2.16"
        dumpcmd "docker system info"
    footer

    header "Docker_DockerDaemonConfig" "Background 2.2 2.3 2.5 2.6 2.7 2.9 2.10 2.11 2.12 2.13 2.14 2.17"
        comment "Use of the daemon.json file is recommended.  See https://docs.docker.com/engine/admin/systemd/"
            dumpfile "/etc/docker" "daemon.json"
        comment "The /etc/default/docker file doesn't apply in systemd-managed systems, which is probably most"
        comment "Docker deployements on Ubuntu or Redhat. See the comment in the file."
            dumpfile "/etc/default" "docker"
        comment "The dockerd command line may also include specific override parameters"
            dumpcmd "ps -f -C dockerd"
    footer

    header "Docker_ContainerList" "Background"
        dumpcmd "docker container ls --all"
    footer

    header "Docker_ImageList" "Background 4.2"
        dumpcmd "docker image ls"
    footer

    header "Docker_ContextList" "Background"
        dumpcmd "docker context ls"
    footer

    header "Docker_Networks" "Background 2.1 5.29"
        comment "Understanding how containers use the network  is a core concept to understandind how Docker workloads"
        comment "are secured.  For an overview of Docker networking, see https://docs.docker.com/network/"
        dumpcmd "docker network ls"
        # Display detailed info about each network
        for n in $(docker network ls --quiet); do
            SECTION="Docker_Networks-$n"
            dumpcmd "docker network inspect $n"
        done
    footer

    header "Docker_PluginsList" "Background"
        comment "Docker plugins extend basic functionality.  See https://docs.docker.com/engine/extend/legacy_plugins/"
        comment "for more information."
        dumpcmd "docker plugin ls"
    footer

    header "Docker_DiskUsage" "Background"
        dumpcmd "docker system df"
    footer

    header "Docker_Volumes" "Background"
        dumpcmd "docker volume ls"
        # Display detailed info about each volume
        for n in $(docker volume ls --quiet); do
            SECTION="Docker_Volumes-$n"
            dumpcmd "docker volume inspect $n"
        done
    footer

    header "Docker_Logs" "Background"
        comment "We'll grab the most recent 25 lines of each active container's log file."
        for n in $(docker container ls --quiet); do
            SECTION="Docker_Logs-$n"
            dumpcmd "docker logs --tail 25 --timestamps $n"
        done
    footer

    header "Docker_FSMount" "1.2.1"
        comment "Docker defaults to /var/lib/docker to store it's images.  This disk can fill up quickly and can"
        comment "system-wide issues if it's part of the root volume.  The following test will determine if /var/lib/docker"
        comment "is it's own mount point."

        # Grep for /var/lib/docker followed by any white space
        RESULT=$(grep "/var/lib/docker\s" /proc/mounts)

        debug "RESULT length: ${#RESULT}"
        debug "RESULT: $RESULT"

        if [ -n "$RESULT" ]; then
            # If the length is RESULT > 0, print the results
            dumpcmd "echo $RESULT"
        else
            # if Grep didn't return any results...
            dumpcmd "echo /var/lib/docker does not appear to be on its own mount point"
        fi
    footer

    header "Docker_Group" "1.2.2"
        dumpcmd "getent group docker"
    footer

    header "Docker_AuditD" "1.2.3 1.2.4 1.2.5 1.2.6 1.2.7 1.2.8"
        comment "Checking if auditd is monitoring the Docker binaries and directories"
            ITEMS=(/usr/bin/docker /usr/bin/containerd /var/lib/docker /usr/sbin/runc)

            for ITEM in ${ITEMS[*]}; do
                if [ -e $ITEM ]; then
                    # If ITEM exists as a file or directory...
                    dumpcmd "auditctl -l | grep $ITEM"
                fi
            done

        comment "Checking if auditd is monitoring Docker config files"
            comment "Docker can be configured in a number of ways based on SystemD, Upstart, etc."
            comment "We'll try to catch them all and report if they weren't found."
            
            # Declare an array with the items we need to check.  
            ITEMS=(/etc/docker/daemon.json /etc/default/docker /etc/sysconfig/docker)

            # Loop through each item in the array
            for ITEM in ${ITEMS[*]}; do
                if [ -e $ITEM ]; then
                    # If ITEM exists as a file or directory...
                    dumpcmd "auditctl -l | grep $ITEM"
                else
                    comment "$ITEM doesn't exist."
                fi
            done

        comment "Checking if auditd is monitoring Docker Systemd objects"
            # Declare an array with the items we need to check.  The specific path to these objects varies based 
            # on RPM or DEB-based systems, so we need to search for them using getFragmentPath function declared above
            ITEMS=(docker.service docker.socket)

            # Loop through each item in the array
            for ITEM in ${ITEMS[*]}; do
                getFragmentPath "$ITEM"

                if [ -n $FRAGPATH ]; then
                # If FRAGPATH returned a path, look for it in auditctl rules
                    dumpcmd "auditctl -l | grep $ITEM"
                else
                # else report that nothing was found
                    comment "$ITEM does not exist"
                fi
            done
    footer

    header "Docker_FilePermissions" "3.x"

        ITEMS=(/var/run/docker.sock /etc/default/docker /etc/sysconfig/docker)
        SYSTEMCTL_ITEMS=(docker.service docker.socket)

        # Add any files and directories found under /etc/docker
        for n in $(find /etc/docker); do
            ITEMS+=("$n")
        done

        # This list needs to processed by getFragmentPath first. We'll add to the end of the ITEMS array
        for ITEM in ${SYSTEMCTL_ITEMS[*]}; do
            getFragmentPath "$ITEM"

            if [ -n $FRAGPATH ]; then
            # If FRAGPATH returned a path, add the path to the end of the ITEMS array
                ITEMS+=($FRAGPATH)
            else
            # else report that nothing was found
                comment "$ITEM does not exist"
            fi
        done

        debug "$SECTION items to check: ${ITEMS[*]}"

        # Now loop through the final ITEMS array        
        for ITEM in ${ITEMS[*]}; do
            if [ -e $ITEM ]; then
            # If $ITEM exists, stat the file
                dumpcmd "stat $ITEM"
            else
            # else report that nothing was found
                comment "$ITEM does not exist"
            fi
        done
    footer

    header "Docker_ContainerDetails" "4.1 4.3 4.4 5.x"
        comment "This check pulls some details from each active container, including:"
        comment "   - The container configuration details such OS privileges, memory/CPU quotas, open ports, etc."
        comment "   - The user ID the container is running as (e.g. 0 = root)"
        comment "   - The packages installed within the container"
        comment "   - The list of out-of-date packages within the container"
        comment "   - The list of processes running in the container (e.g. ps -ef)"
        comment "   - NGinx configurations as this is a popular container we find in production stacks"

        echo -e "[*] Collecting container details, which could take a while on systems with lots of active containers.\n[*] Please wait..."

        # Iterate through the list of active/running containers
        for CONTAINER in $(docker ps --quiet); do
            CONTAINERNAME=$(docker inspect $CONTAINER --format '{{ .Name }}')
            echo -e "[*] Collecting $CONTAINERNAME"
            SECTION="Docker_ContainerDetails-$CONTAINERNAME-Config"
            dumpcmd "docker container inspect $CONTAINER"
            
            SECTION="Docker_ContainerDetails-$CONTAINERNAME-UserID"
            CONTAINERUID=$(docker exec $CONTAINER cat /proc/1/status | grep ^Uid: | awk '{print $3}')
            dumpcmd "echo Container UID=$CONTAINERUID"
            dumpcmd "docker exec $CONTAINER id $CONTAINERUID"

            SECTION="Docker_ContainerDetails-$CONTAINERNAME-InstalledPackages"
            # Since we can't sure if it's RPM-based or DPKG-based inside the container, try both.  One will error out.
            comment "Attempting to get the list of installed packages.  It's possible that the builder might have removed"
            comment "the package management tools from the container.  If that the case, then both of these commands will fail."
            dumpcmd "docker exec $CONTAINER rpm -qa"
            dumpcmd "docker exec $CONTAINER dpkg-query --list"

            SECTION="Docker_ContainerDetails-$CONTAINERNAME-Updates"
            # Since we can't sure if it's RPM-based or DPKG-based inside the container, try both.  One will error out.
            comment "Attempting to get the list of installed packages.  It's possible that the builder might have removed"
            comment "the package management tools from the container.  If that the case, then both of these commands will fail."
            # For RPM-based containers
            dumpcmd "docker exec $CONTAINER yum list updates"
            # For DEB-based containers / Note: This will NOT actually install any updates inside the container.
            dumpcmd "docker exec $CONTAINER apt-get update"
            dumpcmd "docker exec $CONTAINER apt-get -V -u upgrade --assume-no"
            
            SECTION="Docker_ContainerDetails-$CONTAINERNAME-RunningProcesses"
            dumpcmd "docker exec $CONTAINER ps -ef"
        
            SECTION="Docker_ContainerDetails-$CONTAINERNAME-NginxConfig"
            comment "nginx (\"Engine X\") is another popular web server, so we'll grab the config files here."
            comment "The files usually in the \"conf.d\" directory are used to set up the sites that the web server will provide."
            comment "See https://docs.nginx.com/nginx/admin-guide/security-controls/ for documetnation on nginx security."
            comment "This section is based on a default NGINX container provided by NGinx directly.  If a customer has customized their build or moved the config files, the script will report"
            comment "no results, even though NGINX is running in the container."
            dumpcmd "docker exec -it $CONTAINER /bin/cat /etc/nginx/nginx.conf"

            #This one took some work.  Cat'ing an entire directory through the Docker Exec command doesn't seem to work correctly.  So, I had to use a Docker Exec ls to get the file names
            #and then use "tr" to remove the "carriage return" from the results before giving that back to docker exec /bin/cat...
            #Seems to work on Ubuntu 20.04 so far anyway.
            CONFFILES=$(docker exec -it $CONTAINER ls -1 /etc/nginx/conf.d/)
            for FILE in $(echo $CONFFILES | tr -d "\r"); do
                dumpcmd "docker exec -it $CONTAINER /bin/cat /etc/nginx/conf.d/$FILE"
            done

        done
    footer

    header "Docker_ImageHistory" "4.2 4.6 4.7 4.8"
        comment "Several CIS benchmark checks require looking at the image history to determine the pedigree of the image."
        
        # Iterate through the list of images
        for IMAGE in $(docker image ls --quiet); do
            IMAGENAME=$(docker inspect $IMAGE --format '{{ .RepoTags }}')
            SECTION="Docker_ImageHistory-$IMAGENAME"
            dumpcmd "docker history $IMAGE"
        done
    footer
}

function WorldFiles {
    # This check can take a while.  It's preferred to leave it in place, but if mounting several NFS 
    # points or under similar configurations, this can be disabled by running the script with the -w parameter
    # or by responding "n" to the following prompt.

    # If the search for world-readable files hasn't already been disabled by the -w switch, provide an opportunity
    # to disable it here.  Wait for 30 seconds and if an "n" was provided, skip the check.

    comment "This check will report all world-writable files.  Many of these should just be ignored -- everythin in /run, /proc, etc.  But after you filter out those results,"
    comment "there might be some interesting things left.  If you see something in /etc, /home, /bin, /usr/bin and other important binary, configuration or user directories, it'll be worth asking the customer about them."
    if [ $WORLDFILES -eq 1 ]; then
        echo "Searching for world-writable files.  This check can take a while."
        echo "It's preferred to allow this command to run, but can be skipped if a search of all file systems"
        echo "will cause system problems, such as if there a large number of network-mounted NFS volumes."
        echo ""
        
        read -t 30 -n 1 -p "Continue with search for world-writable files? (Y/n)"
        case $REPLY in
            [nN] )
                WORLDFILES=0
                ;;
        esac
    fi

    echo ""

    if [ $WORLDFILES -eq 1 ]; then
        header "WorldFiles" "Background"
            echo -e "[*] Finding world writable files, which could take awhile.\n[*] Please wait..."
            comment  "World Writable Files/Directories"
            dumpcmd "find / ( -type f -o -type d ) -perm /o+w -ls"
        footer
    else
        comment "Search for world-writable files skipped."
    fi
}

clear

# Set some global variables
USER=$(whoami)
NOKUBES=0
DEBUG=0                                                                                 # Holder variable to enable/disable debug mode
DEBUGCMD=0                                                                              # Holder variable to enable/disable debugcmd mode
WORLDFILES=1                                                                            # Holder variable to enable/disable WORLDFILES checking
MODULESUSED=0                                                                           # Variable to track if the -m switch was used to override the modules
MODULESLIST=( System Network Security Logging Users K8sMaster K8sWorker Docker WorldFiles )    # An array to hold the valid list of modules
declare -A SELECTED                                                                     # An associative array to hold the module selections
REPORT_NAME=$(hostname).txt                                                             # Where to write the report to
START_DIR=$(pwd)
RUNLIST=()                                                                              # An array to hold the list of modules to run
if [ -f "${HOME}/.kube/config" ]; then 
# If the user's .kube/config file exists, use that
    KUBEUSERCONFIG="${HOME}/.kube/config"
else 
# otherwise, try the /etc/kubernetes/admin.conf file.  If this doesn't exist, we'll prompt the user for it later
    KUBEUSERCONFIG="/etc/kubernetes/admin.conf"
fi

#Check if running as ROOT / display help and exit if not
if [ "$USER" != "root" ]; then
    echo -e "Not running as ROOT"
    usage
    EXITCODE=1
    exit $EXITCODE
fi

#Initialize the SELECTED list to all 0s
debug "Initilizing SELECTED array"
for MODULE in "${MODULESLIST[@]}"; do
    SELECTED[$MODULE]=0
    debug "$MODULE = ${SELECTED[$MODULE]}"
done

#Get the command line options
while getopts ":cdhkm:w" OPTION; do
    case $OPTION in
        c )
            DEBUGCMD=1
            ;;
        d )
            DEBUG=1
            DEBUGCMD=1
            ;;
        k )
            NOKUBES=1
            ;;
        m )
            debug "OPTARG: $OPTARG"
            debug "Valid modules list: ${MODULESLIST[*]}"

            # Check the provided module name against the official list kept in the $MODULESLIST array defined above.  If it exists, mark it as selected.  If not, throw an error.
            if [[ " ${MODULESLIST[@]} " =~ " $OPTARG " ]]; then
                MODULESUSED=1
                SELECTED[$OPTARG]=1
                debug "$OPTARG = ${SELECTED[$OPTARG]}"
            else 
                usage
                echo -e "\tERROR: Invalid module name"
                EXITCODE=1
                exit $EXITCODE
            fi
            ;;
        w )
            WORLDFILES=0
            ;;
        * )
            usage
            EXITCODE=1
            exit $EXITCODE
            ;;
    esac
done

# If modules were not with the -m option, then select all modules
if [ $MODULESUSED -eq 0 ]; then
    debug "Runlist not set by -m options"
    for MODULE in "${MODULESLIST[@]}"; do
        SELECTED[$MODULE]=1
        debug "$MODULE = ${SELECTED[$MODULE]}"
    done
fi

# Check if K8sMaster has been selected and check for the KUBEUSERCONFIG file.  If it doesn't exist, prompt the user for one
if [ ${NOKUBES} -eq 1 ]; then
    SELECTED[K8s]=0
    SELECTED[K8sMaster]=0
    SELECTED[K8sWorker]=0
fi

if [ ${SELECTED[K8sMaster]} -eq 1 ]; then 
    KUBECTL="kubectl --kubeconfig $KUBEUSERCONFIG"
    while [ ! -f "$KUBEUSERCONFIG" -a "$KUBEUSERCONFIG" != "none" ]; do
        echo "$KUBEUSERCONFIG does not exist."
        read -p "Provide a path to a Kube user config file to use (or 'none' to disable Kubernetes Master checks): " KUBEUSERCONFIG
        if [ "$KUBEUSERCONFIG" == "none" ]; then
            SELECTED[K8s]=0
            SELECTED[K8sMaster]=0
            SELECTED[K8sWorker]=0
        else
            KUBECTL="kubectl --kubeconfig $KUBEUSERCONFIG"
        fi
    done
fi

debug "Final selections:"
for MODULE in "${MODULESLIST[@]}"; do 
    debug  "$MODULE=${SELECTED[$MODULE]}"; 
done

if [ -e $REPORT_NAME ]; then
    #Clean up previous runs of the script
    echo -e "Previous report file $REPORT_NAME found.  Deleting..."
    rm $REPORT_NAME
fi

echo -e ''$_{1..50}'+' 2> /dev/null >> $REPORT_NAME
echo -e "[*] Beginning KP Nix Audit Script v$KPNIXVERSION\n[*] Please wait..."
echo "System Report for $(hostname)" > $REPORT_NAME
echo "This report was generated $(date)" 2> /dev/null >> $REPORT_NAME
echo "KPNIXVERSION: $KPNIXVERSION" 2> /dev/null >> $REPORT_NAME
echo -e ''$_{1..50}'+' 2> /dev/null >> $REPORT_NAME

# Always run this check to give context to the system we're looking at
header "System_VersionInformation" "Background"
    comment "Collecting some basic information about the system.  Take a look through this section to find the string (it varies from RPM-based and Debian-based distros) that will let you see"
    comment "in one list which OS types and versions are in use.  You can use that to check online to make sure that all OSes in use are still supported by the vendor."
    dumpcmd "uname -a"
    comment "System Type:"
        dumpcmd "uname -s"
    comment "Node:" 
        dumpcmd "uname -n"
    comment "Machine:"
        dumpcmd "uname -m"
    comment "Kernel Version:"
        dumpcmd "uname"
    comment "Kernel Release:"
        dumpcmd "uname -r"
    comment "OS Release:"
        dumpfile /etc "*-release"
footer

# Run each module
for MODULE in "${MODULESLIST[@]}"; do
    if [ ${SELECTED[$MODULE]} -eq 1 ]; then
        debug "Calling $MODULE"
        $MODULE
        debug "Finished $MODULE"
    else
        comment "$MODULE skipped"
        debug "Skipping module: $MODULE"
    fi
done

echo "[*] Finished KP Nix Audit Script"
echo "[*] Results are located in $REPORT_NAME"