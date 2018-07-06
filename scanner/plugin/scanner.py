#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Plugin for host scanning.
"""

__author__ = 'gsfish'
__version__ = '1.0.0'

import nmap


class Nmap():
    """Nmap plugin.

    Stage: 50
    Site: https://nmap.org/
    """
    def __init__(self, queue, subdomain, **kwargs):
        self.__result_queue = queue
        self.__subdomain = subdomain
        self.__task_id = kwargs['task_id']
        self.__result = {}
        self.__stage = 50
        self.__nmap = nmap.PortScannerYield()


    def __del__(self):
        pass


    def __exec(self, ip_list):
        args = '--script vuln'
        hosts = ' '.join(set(ip_list))
        for progressive_result in self.__nmap.scan(hosts=hosts, arguments=args):
            host = progressive_result[0]
            scan_result = progressive_result[1]
            if not scan_result['scan'].has_key(host):
                continue
            vuln_list = []
            for port, port_info in scan_result['scan'][host]['tcp'].items():
                if port_info.has_key('script'):
                    for vuln in port_info['script'].items():
                        vuln_list.append({'port': port, 'name': vuln[0], 'detail': vuln[1]})
            if not vuln_list:
                continue
            host_vuln = {'ip_addr': host, 'vuln': vuln_list}
            self.__result = {
                'task_id': self.__task_id,
                'stage': self.__stage,
                'result_type': 'host_vuln',
                'result': host_vuln
            }
            self.sync_result()


    def __do2ip(self, subdomain):
        return [str(r['address']) for r in subdomain]


    def start(self):
        ip_list = self.__do2ip(self.__subdomain)
        self.__exec(ip_list)


    def get_result(self):
        """Return the result of Nmap.

        :return: result.
        {
            'ip_addr': ip_addr,
            'vuln':
            [
                {
                    'port': port,
                    'name': name,
                    'detail': detail
                },
                ...
            ]
        }
        """
        return self.__result


    def sync_result(self):
        self.__result_queue.put(self.get_result())
