#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import time
import random
import urllib2
import threading
import Queue
import logging
import ConfigParser
from atexit import register
from stomp import *
from plugin import *


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(filename)s [line:%(lineno)d] %(levelname)s %(message)s',
                    filename='scan.log', filemode='w')

config = ConfigParser.ConfigParser()
config.read('config.ini')

api_status_query = 'http://localhost:8080/task/status/'
api_result_sync = 'http://localhost:8080/task/control/add/'

stomp_host = config.get('stomp', 'host')
stomp_port = config.getint('stomp', 'port')
stomp_user = config.get('stomp', 'username')
stomp_pswd = config.get('stomp', 'password')
stomp_dest = config.get('stomp', 'dest')

lock = threading.Lock()
task_queue = Queue.Queue()
result_queue = Queue.Queue()
current_task = set()


class Worker(threading.Thread):

    def __init__(self, target=None, args=(), name=None, trigger=threading.Event()):
        super(Worker, self).__init__(name=name)
        self.__target = target
        self.__args = args
        self.__trigger = trigger


    def run(self):
        print '[*] %s start...' % threading.currentThread().name
        self.__target(self.__trigger, *self.__args)


    def stop(self):
        self.__trigger.set()


class TaskReceiver(ConnectionListener):

    def on_message(self, headers, body):
        global task_queue
        global current_task

        task = json.loads(body)
        current_task.add(task['task_id'])
        task_queue.put(task)


    def on_connected(self, headers, body):
        global stomp_host, stomp_port, stomp_dest

        print '[*] receiver connected'
        logging.info('reveiver connect stomp://%s:%d%s' % (stomp_host, stomp_port, stomp_dest))


def receive_thread(trigger):
    global lock
    global stomp_host, stomp_port, stomp_user, stomp_pswd, stomp_dest

    c = Connection([(stomp_host, stomp_port)])
    c.set_listener('', TaskReceiver())
    c.start()
    c.connect(stomp_user, stomp_pswd, wait=True)
    c.subscribe(stomp_dest, random.randint(100, 999))
    trigger.wait()
    c.disconnect()
    with lock:
        print '[*] %s stop' % threading.current_thread().name


def status_query_thread(trigger):
    global lock
    global api_status_query
    global task_queue
    global current_task

    while not trigger.is_set():
        for task_id in current_task.copy():
            try:
                status = urllib2.urlopen(api_status_query+str(task_id)).read()
            except Exception:
                logging.exception('thread: %s' % threading.currentThread().name)
                logging.error('error when query status (tid: %d)' % task_id)
                continue
            if status == 'cancel':
                task = {'task_id': task_id, 'task_type': 'cancel'}
                task_queue.put(task)
                current_task.remove(task_id)
        trigger.wait(3)
    with lock:
        print '[*] %s stop' % threading.current_thread().name


def result_sync_thread(trigger):
    global result_queue
    global api_result_sync

    while not trigger.is_set():
        try:
            result = result_queue.get(timeout=1)
        except Queue.Empty:
            continue

        url = '%s%d/%s' % (api_result_sync, result['task_id'], result['result_type'])
        header = {'Content-Type': 'application/json'}
        data = json.dumps(result)

        req = urllib2.Request(url, headers=header, data=data)
        try:
            res = urllib2.urlopen(req)
        except Exception:
            logging.exception('thread: %s' % threading.current_thread().name)
            logging.error('error when sync %s result (tid: %d)' % (result['result_type'], result['task_id']))
            continue
        if res.read() == 'ok':
            logging.info('sync %s result (tid: %d)' % (result['result_type'], result['task_id']))
        elif res.read() == 'error':
            logging.info('fail when sync %s result (tid: %d)' % (result['result_type'], result['task_id']))


def scan_thread(trigger, task):
    global result_queue, current_task

    if trigger.is_set():
        current_task.remove(task['task_id'])
        print '[*] %s stop' % threading.current_thread().name
        return

    plugin_dnsrecon = DNSRecon(result_queue, **task)
    logging.info('launch dnsrecon plugin (tid: %d)' % task['task_id'])
    plugin_dnsrecon.start()
    result_subdomain = plugin_dnsrecon.get_result()
    if trigger.is_set() or not result_subdomain:
        current_task.remove(task['task_id'])
        print '[*] %s stop' % threading.current_thread().name
        return

    plugin_dnsrecon.sync_result()
    if trigger.is_set():
        current_task.remove(task['task_id'])
        print '[*] %s stop' % threading.current_thread().name
        return

    plugin_nmap = Nmap(result_queue, result_subdomain, **task)
    logging.info('launch nmap plugin (tid: %d)' % task['task_id'])
    plugin_nmap.start()
    result_nmap = plugin_nmap.get_result()
    if trigger.is_set() or not result_nmap:
        current_task.remove(task['task_id'])
        print '[*] %s stop' % threading.current_thread().name
        return

    logging.info('task complete (tid: %d)' % task['task_id'])
    current_task.remove(task['task_id'])
    print '[*] %s stop' % threading.current_thread().name


def main_thread():
    global task_queue
    global current_task

    print '[*] %s start' % threading.currentThread().name

    stop_main = threading.Event()
    register(atexit, stop_main, threading.currentThread().name)

    thread_receive = Worker(target=receive_thread, name='ReceiveThread', trigger=stop_main)
    thread_receive.daemon = True
    thread_receive.start()

    thread_status = Worker(target=status_query_thread, name='StatusQueryThread', trigger=stop_main)
    thread_status.daemon = True
    thread_status.start()

    thread_result_sync = Worker(target=result_sync_thread, name='ResultSyncThread', trigger=stop_main)
    thread_result_sync.daemon = True
    thread_result_sync.start()

    while not stop_main.is_set():
        try:
            task = task_queue.get(timeout=1)
        except Queue.Empty:
            continue

        if task['task_type'] == 'scan':
            print '[*] receive scan task: %d' % task['task_id']
            logging.info('receive scan task (tid: %d)' % task['task_id'])
            target_name = 'ScanThread-%d' % task['task_id']
            thread_scan = Worker(target=scan_thread, args=(task,), name=target_name)
            thread_scan.start()
            current_task.add(task['task_id'])

        elif task['task_type'] == 'cancel':
            print '[*] receive cancel task: %d' % task['task_id']
            logging.info('receive cancel task (tid: %d)' % task['task_id'])
            for t in threading.enumerate():
                target_name = 'ScanThread-%d' % task['task_id']
                if t.name == target_name:
                    print '[*] stopping %s' % target_name
                    t.stop()
                    break


def atexit(stop_main, thread_name):
    print'[*] %s stop' % thread_name
    stop_main.set()
    time.sleep(3)


if __name__ == '__main__':
    try:
        main_thread()
    except KeyboardInterrupt:
        pass
