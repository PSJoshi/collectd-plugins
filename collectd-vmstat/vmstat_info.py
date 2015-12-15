#!/usr/bin/env python

import collectd
import subprocess
import datetime
import re
import traceback
import os

VMSTAT_BIN = '/usr/bin/vmstat'


def get_stats():

    vmstats_dict = dict()

    if not os.path.exists(VMSTAT_BIN):
        collectd.error("No vmstat program %s is found on the system" % VMSTAT_BIN)
        return vmstats_dict
    try:
        result = subprocess.Popen([VMSTAT_BIN,'-s'], shell=False, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)

        for line in result.stdout.readlines():
            #digit_list = [ int(d) for d in line.split() if d.isdigit() ]
            #print digit_list
            match = re.match(r"(\d+) (\D+)", line.strip(), re.I)
            if match:
                parsed_vmstats = match.groups()
                key = '_'.join(parsed_vmstats[1].strip().split())
                value = int(parsed_vmstats[0])
                vmstats_dict.update({key:value})
    except Exception as exc:
        collectd.error("Failed to dispatch values - %s : %s" % (exc, traceback.format_exc())
            )
    return vmstats_dict


def configure_callback(conf):
    pass

def read_callback():

    # get vmstat information
    info = get_stats()
    if not info:
        collectd.error("No information received")
        return

    for key in info:
        collectd.info("Dispatching %s : %i" % (key, info[key]))

        val = collectd.Values(plugin='vmstats')
        val.type = 'gauge'
        val.type_instance = key
        val.values = [info[key]]
        val.dispatch()

collectd.register_config(configure_callback)
collectd.register_read(read_callback)
