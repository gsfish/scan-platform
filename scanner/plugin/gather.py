#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Plugin for host information gathering.
"""

__author__ = 'gsfish'
__version__ = '1.0.0'

import os
import json
import subprocess
import logging


class DNSRecon():
    """DNSRecon plugin.

    Stage: 10
    Github: https://github.com/darkoperator/dnsrecon
    """
    def __init__(self, queue, **kwargs):
        self.__result_queue = queue
        self.__task_id = kwargs['task_id']
        self.__domain = kwargs['domain']
        self.__subdomain = []
        self.__stage = 10


    def __del__(self):
        # if os.path.isfile('/tmp/vulscan-dnsrecon-%s.json' % self.__task_id):
        #     os.remove('/tmp/vulscan-dnsrecon-%s.json' % self.__task_id)
        pass


    def __exec(self, domain):
        outfile = '/tmp/vulscan-dnsrecon-%d.json' % self.__task_id
        cmd = ('python dnsrecon.py -asw --threads 5 --json %s --domain' % outfile).split()
        cmd.append(domain)
        cmd_in = 'a\n'

        cwd = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'dnsrecon')
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             cwd=cwd, universal_newlines=True)
        stderr = p.communicate(cmd_in)[1]
        if stderr:
            logging.debug(' '.join(cmd))
            logging.error(stderr.strip())
            return None
        else:
            return outfile


    def start(self):
        for domain in self.__domain:
            outfile = self.__exec(domain)
            if not outfile:
                continue

            result_json = json.load(open(outfile, 'r'))
            result = [
                {'name': r['name'], 'address': r['address']}
                for r in result_json
                if r.has_key('name') and r.has_key('address') and r['address'] != 'no_ip'
            ]
            self.__subdomain.extend(result)


    def get_result(self):
        """Return the result of DNSRecon.

        :return: subdomain.
        [
            {
                'address': ip_addr,
                'name': subdomain
            },
            ...
        ]
        """
        return self.__subdomain


    def sync_result(self):
        result = {
            'task_id': self.__task_id,
            'stage': self.__stage,
            'result_type': 'subdomain',
            'result': self.get_result()
        }
        self.__result_queue.put(result)
