#!/usr/bin/env python

import collectd
import subprocess
import re
import traceback
import os

SYSCTL_BIN = '/sbin/sysctl'
SYSCTL_parameters = [
    # reference - http://www.cyberciti.biz/faq/linux-kernel-etcsysctl-conf-security-hardening/
    ########## IPv4 networking #############
    #IP packet forwarding
    "net.ipv4.ip_forward",
    # Controls source route verification
    "net.ipv4.conf.default.rp_filter",
    # Do not accept source routing
    "net.ipv4.conf.default.accept_source_route",
    # Controls the System Request debugging functionality of the kernel
    "kernel.sysrq",
    #Controls whether core dumps will append the PID to the core filename
    "kernel.core_uses_pid",
    # Controls the use of TCP syncookies
    "net.ipv4.tcp_syncookies",
    "net.ipv4.tcp_synack_retries",
    # Send redirects if router otherwise not
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.default.send_redirects",
    # Accept packets with SRR option
    "net.ipv4.conf.all.accept_source_route",
    # Accept Redirects? No, this is not router
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.all.secure_redirects",
    # Log packets with impossible addresses to kernel log? yes
    "net.ipv4.conf.all.log_martians",
    "net.ipv4.conf.default.accept_source_route",
    "net.ipv4.conf.default.accept_redirects",
    "net.ipv4.conf.default.secure_redirects",
     # Ignore all ICMP ECHO and TIMESTAMP requests sent to it via broadcast/multicast
     "net.ipv4.icmp_echo_ignore_broadcasts",
     # Prevent against the common 'syn flood attack'
     "net.ipv4.tcp_syncookies",
     # Enable source validation by reversed path
     "net.ipv4.conf.all.rp_filter",
     "net.ipv4.conf.default.rp_filter",
     ########## IPv6 networking #############
     # Number of Router Solicitations to send until assuming no routers are present.
    "net.ipv6.conf.default.router_solicitations",
    # Accept Router Preference in RA?
    "net.ipv6.conf.default.accept_ra_rtr_pref",
    # Learn Prefix Information in Router Advertisement
    "net.ipv6.conf.default.accept_ra_pinfo",
    # Setting controls whether the system will accept Hop Limit settings from a router advertisement
    "net.ipv6.conf.default.accept_ra_defrtr",
    #router advertisements can cause the system to assign a global unicast address to an interface
    "net.ipv6.conf.default.autoconf",
    #how many neighbor solicitations to send out per address?
    "net.ipv6.conf.default.dad_transmits",
    # How many global unicast IPv6 addresses can be assigned to each interface?
    "net.ipv6.conf.default.max_addresses",
    #Enable ExecShield protection
    "kernel.exec-shield",
    "kernel.randomize_va_space",
    # increase Linux auto tuning TCP buffer limits
    "net.core.rmem_max",
    "net.core.wmem_max",
    "net.core.netdev_max_backlog",
    "net.ipv4.tcp_window_scaling",
    # increase system file descriptor limit
    "fs.file-max",
    #Allow for more PIDs
    "kernel.pid_max"
]

def subprocess_response(sysctl_parameter):

    # initialize arguments to subprocess
    sysctl_args = [SYSCTL_BIN,'-a']
    #sysctl_args = ['/sbin/sysctl','-a']
    grep_args = ['grep']
    grep_args.append(sysctl_parameter)
    try:
        process_sysctl = subprocess.Popen(sysctl_args, shell=False, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
        process_grep = subprocess.Popen(grep_args, stdin=process_sysctl.stdout,
                                  stdout=subprocess.PIPE, shell=False)
        # Allow process_sysctl to receive a SIGPIPE if process_grep exits.
        process_sysctl.stdout.close()
        return process_grep.communicate()[0]
    except Exception as exc:
        collectd.error("Error while getting subprocess response - %s : %s" % (exc, traceback.format_exc()))
        return None


def get_stats():

    sysctl_dict = dict()

    if not os.path.exists(SYSCTL_BIN):
        collectd.error("No sysctl program %s is found on the system" % SYSCTL_BIN)
        return sysctl_dict
    # find response for each sysctl parameter
    for parameter in SYSCTL_parameters:
        collectd.info("Checking parameter setting - %s" %parameter)
        response = subprocess_response(parameter)
        collectd.info(" Present %s sysctl parameter setting is : %s" %(parameter, response))
        if response and response.find("=")>=0:
            r = response.strip().split('=')
            sysctl_dict.update({r[0].strip(): int(r[1])})

    return sysctl_dict


def configure_callback(conf):
    pass

def read_callback():

    # get vmstat information
    info = get_stats()
    if not info:
        collectd.error("No sysctl parameters information received")
        return

    for key in info:
        collectd.info("Dispatching %s : %i" % (key, info[key]))

        val = collectd.Values(plugin='sysctl')
        val.type = 'gauge'
        val.type_instance = key
        val.values = [info[key]]
        val.dispatch()

collectd.register_config(configure_callback)
collectd.register_read(read_callback)

