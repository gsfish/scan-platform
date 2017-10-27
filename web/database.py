#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import json
import hashlib
import logging
import ConfigParser
import MySQLdb
from flask import abort


config = ConfigParser.ConfigParser()
config.read('config.ini')
db_config = {
    'host': config.get('database', 'host'),
    'user': config.get('database', 'username'),
    'passwd': config.get('database', 'password'),
    'db': config.get('database', 'database')
}


class Database():

    def __init__(self):
        global db_config

        self.conn = MySQLdb.connect(**db_config)
        self.curs = self.conn.cursor()


    def __del__(self):
        self.curs.close()
        self.conn.close()


    def gen_uid(self, username, password):
        sha256 = hashlib.sha256()
        sha256.update(str(time.time()))
        sha256.update(username)
        sha256.update(password)
        return sha256.hexdigest()[:32]


    def gen_hash(self, username, password):
        salt = 'vulscan'
        sha256 = hashlib.sha256()
        sha256.update(hashlib.sha256(username+salt).hexdigest()+password)
        return sha256.hexdigest()[:32]


    def create_user(self, username, password):
        uid = self.gen_uid(username, password)
        password = self.gen_hash(username, password)
        sql = 'INSERT INTO login(uid, username, password) VALUES (%s, %s, %s);'
        parm = (uid, username, password)
        try:
            self.curs.execute(sql, parm)
        except Exception:
            self.conn.rollback()
            logging.exception('sql: %s' % sql)
            abort(500)
        else:
            self.conn.commit()
            return True


    def check_user(self, username, password):
        password = self.gen_hash(username, password)
        sql = 'SELECT uid FROM login WHERE username = %s AND password = %s;'
        parm = (username, password)
        try:
            self.curs.execute(sql, parm)
        except Exception:
            logging.exception('sql: ' % sql)
            abort(500)
        else:
            if self.curs.rowcount != 0:
                uid = self.curs.fetchone()[0]
                return uid
        else:
                return False


    def create_task(self, tid, uid, domain, ip_addr, ctime, type):
        sql = 'INSERT INTO task(tid, uid, domain, ip_addr, ctime, type) VALUES (%s, %s, %s, %s, %s, %s);'
        parm = (tid, uid, domain, ip_addr, ctime, type)
        try:
            self.curs.execute(sql, parm)
        except Exception:
            self.conn.rollback()
            logging.exception('sql: %s' % sql)
            abort(500)
        else:
            self.conn.commit()
            return True


    def check_task_info(self, uid):
        sql = 'SELECT tid, ctime FROM task WHERE uid = %s ORDER BY ctime DESC;'
        parm = (uid,)
        try:
            self.curs.execute(sql, parm)
        except Exception:
            logging.exception('sql: %s' % sql)
            abort(500)
        else:
            fetch_result = self.curs.fetchall()
            result = [{'tid': row[0], 'ctime': row[1]} for row in fetch_result]
            return result


    def check_task_status(self, tid):
        sql = 'SELECT type FROM task WHERE tid = %s;'
        parm = (tid,)
        try:
            self.curs.execute(sql, parm)
        except Exception:
            logging.exception('sql: %s' % sql)
            abort(500)
        else:
            if self.curs.rowcount != 0:
                type = self.curs.fetchone()[0]
                return type
            else:
                return 'null'


    def change_task_status(self, tid, want):
        if want == 0:
            task_type = 'cancel'
        else:
            task_type = 'scan'
        sql = 'UPDATE task SET type = %s WHERE tid = %s;'
        parm = (task_type, tid)
        try:
            self.curs.execute(sql, parm)
        except Exception:
            logging.exception('sql: %s' % sql)
            abort(500)
        else:
            if self.curs.rowcount != 0:
                return True
            else:
                return False


    def create_task_result(self, tid, pid, type, result):
        sql = 'INSERT INTO result(tid, pid, type, result) VALUES (%s, %s, %s, %s)'
        parm = (tid, pid, type, result)
        try:
            self.curs.execute(sql, parm)
        except Exception:
            self.conn.rollback()
            logging.exception('sql: %s' % sql)
            abort(500)
        else:
            self.conn.commit()
            return True


    def check_task_result(self, tid, type):
        sql = 'SELECT result FROM result WHERE tid = %s AND type = %s'
        parm = (tid, type)
        try:
            self.curs.execute(sql, parm)
        except Exception:
            logging.exception('sql: %s' % sql)
            abort(500)
        else:
            if self.curs.rowcount != 0:
                results = self.curs.fetchall()
                return [json.loads(r[0]) for r in results]
            else:
                return ()
