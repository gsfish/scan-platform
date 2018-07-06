#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import time
import random
import logging
import ConfigParser
from flask import *
from stomp import *
from database import Database


logging.logging.basicConfig(level=logging.logging.DEBUG, format='%(asctime)s %(filename)s [line:%(lineno)d] %(levelname)s %(message)s',
                    filename='web.log', filemode='w')

config = ConfigParser.ConfigParser()
config.read('config.ini')

app = Flask(__name__)
app.secret_key = config.get('app', 'secret_key')

stomp_host = config.get('stomp', 'host')
stomp_port = config.getint('stomp', 'port')
stomp_user = config.get('stomp', 'username')
stomp_pswd = config.get('stomp', 'password')
stomp_dest = config.get('stomp', 'dest')


def get_login():
    if session.get('login'):
        return True
    else:
        return False


def vaild_login(username, password):
    db = Database()
    # if db.create_user(username, password):
    #     return True
    # else:
    #     return False
    uid = db.check_user(username, password)
    if uid:
        session['uid'] = uid
        return True
    else:
        return False


def send_task(data):
    global stomp_host, stomp_port, stomp_user, stomp_pswd, stomp_dest

    c = Connection([(stomp_host, stomp_port)])
    c.start()
    try:
        c.connect(stomp_user, stomp_pswd, wait=True)
    except Exception:
        logging.exception('STOMP CONNECT: stomp://%s:%s' % (stomp_host, stomp_port))
        return False

    try:
        c.send(stomp_dest, data)
    except Exception:
        logging.exception('STOMP SEND: stomp://%s:%s' % (stomp_host, stomp_port))
        return False
    else:
        return True
    finally:
        c.disconnect()


def start_scan(form):
    task_id = random.randint(100000, 999990)
    form_domain = form['domain'].strip()
    form_ip = form['ip_addr'].strip()

    if form_domain:
        domain_list = [d.strip() for d in form_domain.split(';') if d.strip()]
    else:
        domain_list = []
    if form_ip:
        ip_list = [i.strip() for i in form_ip.split(';') if i.strip()]
    else:
        ip_list = []

    task_data = {
        'domain': domain_list,
        'ip_addr': ip_list,
        'cookies': form['cookies'].strip() or None,
        'task_id': task_id,
        'task_type': 'scan'
    }
    task_msg = json.dumps(task_data)

    tid = task_id
    uid = session['uid']
    ctime = time.strftime("%Y-%m-%d %H:%M:%S")
    domain = '; '.join(domain_list)
    ip_addr = '; '.join(ip_list)
    type = 'scan'
    db = Database()
    if db.create_task(tid, uid, domain, ip_addr, ctime, type) and send_task(task_msg):
        return task_id
    else:
        return False


def filter_stage(value, numeric=False):
    if numeric:
        if not value:
            return 0
        return int(value / 10) * 10
    else:
        if not value:
            return 'danger'
        if value < 100:
            return 'warning'
        if value == 100:
            return 'success'


def filter_omit(value):
    max_len = 30
    if len(value) > max_len:
        return value[:max_len-3] + '...'
    else:
        return value


@app.route('/')
def index():
    # return render_template('index.html')
    return redirect(url_for('login'))


@app.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if not session.get('login'):
            return render_template('login.html')
        else:
            return redirect(url_for('dashboard'))

    elif request.method == 'POST':
        if vaild_login(request.form['username'], request.form['password']):
            session['user'] = request.form['username']
            session['login'] = True
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', invaild=True)


@app.route('/logout/')
def logout():
    session.pop('login', None)
    session.pop('user', None)
    return redirect(url_for('login'))


@app.route('/dashboard/')
def dashboard():
    if not get_login():
        return redirect(url_for('login'))
    db = Database()
    result = db.check_task_stage_count()
    count = {
        's1': result[0],
        's2': result[1],
        's3': result[2],
        's4': result[3],
        's5': result[4]
    }
    return render_template('dashboard/overview.html', count=count)


@app.route('/dashboard/setting/')
def dashboard_setting():
    if not get_login():
        return redirect(url_for('login'))
    return render_template('dashboard/setting.html')


@app.route('/dashboard/workflow/')
def dashboard_workflow():
    if not get_login():
        return redirect(url_for('login'))
    return render_template('dashboard/workflow.html')


@app.route('/task/status/<int:task_id>')
def task_status(task_id):
    db = Database()
    status = db.check_task_status(task_id)
    return status


@app.route('/task/control/cancel/<int:task_id>')
def task_control_cancel(task_id):
    db = Database()
    if db.change_task_status(task_id, 0):
        return 'ok'
    else:
        return 'error'


@app.route('/task/control/add/<int:task_id>/<result_type>', methods=['POST'])
def task_control_add(task_id, result_type):
    if not request.json or not request.json.get('task_id') or not request.json.get('stage') or not request.json.get('result_type'):
        abort(400)

    task_id = request.json.get('task_id')
    stage = request.json.get('stage')
    result_type = request.json.get('result_type')
    result = json.dumps(request.json.get('result'))
    db = Database()
    if db.create_task_result(task_id, stage, result_type, result):
        return 'ok'
    else:
        return 'error'


@app.route('/task/control/check/<int:task_id>/<result_type>')
def task_control_check(task_id, result_type):
    db = Database()
    results = db.check_task_result(task_id, result_type)
    return jsonify(results)


@app.route('/dashboard/scan/', methods=['GET', 'POST'])
def dashboard_scan():
    if not get_login():
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('dashboard/scan.html')

    elif request.method == 'POST':
        if request.form['ip_addr'] or request.form['domain']:
            task_id = start_scan(request.form)
            if task_id:
                return render_template('dashboard/scan.html', status='ok', task_id=task_id)
        return render_template('dashboard/scan.html', status='error')


@app.route('/dashboard/result/')
def dashboard_result():
    if not get_login():
        return redirect(url_for('login'))
    uid = session['uid']
    db = Database()
    task = db.check_task_info(uid)
    return render_template('dashboard/result.html', task=task)


@app.route('/dashboard/result/detail/<int:task_id>')
def dashboard_result_detail(task_id):
    if not get_login():
        return redirect(url_for('login'))
    db = Database()
    stage = db.check_task_stage(task_id)
    subdomain = db.check_task_result(task_id, 'subdomain')
    host_vuln = db.check_task_result(task_id, 'host_vuln')
    result = {
        'task_id': task_id,
        'stage': stage,
        'subdomain': subdomain,
        'host_vuln': host_vuln
    }
    return render_template('dashboard/result_detail.html', result=result)


@app.route('/dashboard/result/detail/<int:task_id>/<int:port>/<name>')
def dashboard_result_port_detail(task_id, port, name):
    if not get_login():
        return redirect(url_for('login'))
    db = Database()
    stage = db.check_task_stage(task_id)
    host_vuln = db.check_task_result(task_id, 'host_vuln')
    result = {
        'task_id': task_id,
        'stage': stage,
        'port': port,
        'name': name,
        'host_vuln': host_vuln
    }
    return render_template('dashboard/result_vuln_detail.html', result=result)


@app.route('/dashboard/relation/')
def dashboard_relation():
    if not get_login():
        return redirect(url_for('login'))
    return render_template('dashboard/relation.html')


@app.route('/dashboard/export/')
def dashboard_export():
    if not get_login():
        return redirect(url_for('login'))
    return render_template('dashboard/export.html')


if __name__ == '__main__':
    app.jinja_env.trim_blocks = True
    app.jinja_env.filters['cus_stage'] = filter_stage
    app.jinja_env.filters['cus_omit'] = filter_omit
    app.run(host='0.0.0.0', port=8080, debug=False)
