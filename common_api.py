# -*- coding:utf-8 -*-
# import datetime
from flask import Blueprint, request, Response
import json
import os, shutil
from service import version_service, time_service, system_service, network_service, l2tp_service, ca_service
from common.persistence import Persistence
from common import constants
from common.small_logger import SmallLogger
import gdi
import traceback
import subprocess
import time
import random

common_api = Blueprint('common_api', __name__)

def ranstr(num=4):
    H = 'abcdefghijklmnopqrstuvwxyz'
    salt = ''
    for i in range(num):
        salt += random.choice(H)

    return salt

@common_api.route("/all", methods=["GET"])
def all_api():
    v = version_service.read_version()
    t = time_service.get_time()
    n = Persistence.network
    # u = user_service.get_admin()
    d = str(Persistence.date_obj)
    t = str(Persistence.time_obj)
    st = int(time.time())
    et = int(Persistence.edited_time)

    if et == 0:
        et = time.time()

    redirect = "https://" + n['host_ip']
    m = {
        "version": v,
        "time": t,
        "network": n,
        # "user": u,
        "calendar_date": d,
        "calendar_time": t,
        "system_time": st,
        "redirect": redirect,
        "et": et,
        "error_code": Persistence.get_error_code(),
        "error_code_info": constants.error_code_info.get(Persistence.get_error_code()),
        "service_timeout": Persistence.get_service_timeout(),
        "backuplist": Persistence.get_backuplist(),
        "service_count": Persistence.get_service_count()
    }
    result = json.dumps(m)
    return result


@common_api.route("/version", methods=['GET'])
def version_api():
    v = version_service.read_version()
    jm = json.dumps(v)
    return jm


def send_status_code(status_code=200):
    res = Response(status=status_code, mimetype="application/json")
    return res


def make_response_with_data(result, status_code=200):
    res = Response(response=result, status=status_code, mimetype="application/json")
    return res


def make_response(success=True, msg=None, status_code=200):
    m = {
        "success": success,
        "msg": msg,
    }
    result = json.dumps(m)
    res = Response(response=result, status=status_code, mimetype="application/json")
    return res


@common_api.route(constants.ROOT_API + "/network", methods=["GET", "POST"])
def change_ip_api():
    if request.method == "GET":
        n = network_service.get_network_info()
        jm = json.dumps(n)
        return make_response_with_data(jm)
    elif request.method == "POST":
        req = request.get_json(force=True)
        if network_service.change_only_ip(req) is True:
            return make_response()
        else:
            return make_response(success=False, status_code=400)
    else:
        return send_status_code(status_code=400)


@common_api.route(constants.ROOT_API + "/time", methods=["GET", "POST"])
def system_time():
    if request.method == "GET":
        result = time_service.get_current_time()
        return make_response_with_data(result)
    else:
        req = request.get_json(force=True)
        # 2015-05-15T18:33:35Z
        result = time_service.set_current_time(req.get("time"))
        if result is True:
            return make_response(success=True, msg='ok', status_code=200)
        else:
            return send_status_code(400)


@common_api.route(constants.ROOT_API + "/ntp", methods=["POST"])
def set_ntp_ip():
    try:
        if request.method == "POST":
            req = request.get_json(force=True)
            activate_ntp = req.get("activateNtp")
            new_ip = req.get("new_ip")
            if not new_ip:
                return send_status_code(400)
            p = subprocess.Popen(('/usr/sbin/ntpdate -q %s' % (new_ip)).split(), stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            out, error = p.communicate()
            # print out,error
            p_code = p.returncode
            if p_code <> 0:
                return make_response(success=False, msg='the IP :%s has not ntp service' % new_ip, status_code=200)
            status = [0, 1][activate_ntp == True]
            result = time_service.set_ntp_ip(new_ip, status)
            time_service.activate_ntp()

            if result is True:
                return make_response(success=True, msg='ok', status_code=200)
            else:
                return send_status_code(400)

    except:
        traceback.print_exc()
        return send_status_code(400)


@common_api.route(constants.ROOT_API + "/poweroff/mw", methods=["POST"])
def poweroff_mw():
    if request.method == "POST":
        result = system_service.poweroff_system()
        if result is True:
            return send_status_code(200)
        else:
            return send_status_code(400)


@common_api.route(constants.ROOT_API + "/restart/mw", methods=["POST"])
def restart_mw():
    if request.method == "POST":
        result = system_service.reboot_system()
        if result is True:
            return send_status_code(200)
        else:
            return send_status_code(400)


@common_api.route(constants.ROOT_API + "/factoryreset/mw", methods=["POST"])
def factory_reset_mw():
    if request.method == "POST":
        req = request.get_json(force=True)
        result = system_service.factory_reset()
        username = str(req.get("username"))
        ip = str(req.get("ip"))
        utc_time = time_service.get_utc_time()
        SmallLogger.get_logger().info(
            "\n-----------------\nfactory reset success?: %s\nusername: %s\nip: %s\nutc time: %s\n", str(result),
            username, ip, utc_time)
        if result is True:
            return send_status_code(200)
        else:
            return send_status_code(400)


@common_api.route(constants.ROOT_API + "/systemstat", methods=["GET"])
def api_systemstat():
    if request.method == "GET":
        res = system_service.get_mw_system_stat()
        res_json = json.dumps(res)
        return make_response_with_data(result=res_json)
    else:
        return send_status_code(status_code=400)


@common_api.route(constants.ROOT_API + "/config", methods=["GET", "PUT"])
def api_system_config():
    if request.method == "GET":
        res = system_service.get_system_config()
        res_json = json.dumps(res)
        return make_response_with_data(result=res_json)


@common_api.route(constants.ROOT_API + "/restart_process", methods=['POST'])
def restart_api():
    if request.method == "POST":
        system_service.restart_process()
        m = {
            "result": True
        }
        return make_response(msg=m)


@common_api.route(constants.ROOT_API + "/backup/conf", methods=["POST"])
def backup_system_all():
    if request.method == "POST":
        try:
            req = request.get_json(force=True)
            backupPath = str(req.get("backupPath"))
            tables = req.get("tableNameList")
            hasPassword = req.get("hasPassword")
            password = req.get("password")
            path = str(backupPath[:-len(backupPath.split(os.sep)[-1]) - 1]).strip()
            fileName = str(backupPath.split(os.sep)[-1]).strip()
            path_tmp = path + '/tmp'
            if not backupPath or not path or not fileName or not password or hasPassword is None:
                return make_response(success=False, msg='B07', status_code=200)

            if hasPassword is True:
                if not password:
                    # passw is error
                    return make_response(success=False, msg='B00', status_code=200)
            if not fileName or not path or not os.path.exists(path):
                # file path is not error
                return make_response(success=False, msg='B01', status_code=200)

            # clean old backfile
            if os.path.exists(backupPath):
                os.system('rm -rf %s' % backupPath)
            # os.system('rm -rf %s' % path_tmp)
            # back db table
            if len(tables) != 0:
                result = gdi.process_sqldump_by_tables(path, tables)
                if not result:
                    return make_response(success=False, msg='B02', status_code=200)
            else:
                result, dir = gdi.process_sqldump(path)
                if not result:
                    return make_response(success=False, msg='B02', status_code=200)

            # back mw
            result = gdi.backup_mw_config(path_tmp)
            if not result:
                return make_response(success=False, msg='B03', status_code=200)

            # back dpi
            result = gdi.backup_dpi_config(path_tmp)
            if not result:
                return make_response(success=False, msg='B04', status_code=200)

            # tar file by password
            if hasPassword:
                p = subprocess.Popen(
                    ('%s %s %s %s' % (constants.mw_conf_back_script, path, fileName, password)).split(),
                    stdout=subprocess.PIPE).wait()
            else:
                p = subprocess.Popen(('%s %s %s' % (constants.mw_conf_back_script, path, fileName)).split(),
                                     stdout=subprocess.PIPE).wait()
            # out, error = p.communicate()
            # print out, error,p.returncode
            # os.system('''%s %s''' % (constants.mw_conf_back_script, path,passw))
            # os.system('tar -zcvf - /tmp/back_up/tmp|openssl des3 -salt -k password | dd of=tmp.des3')
            if not os.path.isfile(path + '/' + fileName):
                # tar file error
                return make_response(success=False, msg='B05', status_code=200)
            # os.system('rm -rf %s' % (path + '/tmp'))
            return make_response(success=True, msg='A00', status_code=200)
        except:
            SmallLogger.get_logger().info(traceback.format_exc())
            # os.system('rm -rf %s' % path)
            return make_response(success=False, msg='B06', status_code=200)


@common_api.route(constants.ROOT_API + "/system/delete", methods=["POST"])
def api_delete():
    if request.method == "POST":
        req = request.get_json(force=True)
        path = str(req.get("path"))
        result, msg = system_service.delete_path(path)
        m = {
            "result": result,
            "msg": msg
        }
        jm = json.dumps(m)
        if result is True:
            return make_response_with_data(result=jm, status_code=200)
        else:
            return make_response_with_data(result=jm, status_code=500)


# @common_api.route(constants.ROOT_API + "/system/runningmode", methods=["GET", "POST"])
# def change_management_model_api():
#     if request.method == "GET":
#         m = network_service.get_management_mode()
#         jm = json.dumps(m)
#         return make_response_with_data(jm)
#     elif request.method == "POST":
#         req = request.get_json(force=True)
#         if network_service.set_management_mode(req) is True:
#             return make_response()
#         else:
#             return make_response(success=False, status_code=400)
#     else:
#         return send_status_code(status_code=400)


@common_api.route(constants.ROOT_API + "/serial", methods=["GET"])
def api_get_dpi_serial():
    if request.method == "GET":
        serial = Persistence.device_serial
        if not serial:
            SmallLogger.get_logger().info("first get serial nu before:%s" % serial)
            res = system_service.read_serial()
            Persistence.device_serial = res
            SmallLogger.get_logger().info("first get serial nu after:%s" % res)
        else:
            res = serial
            # SmallLogger.get_logger().info("get serial nu :%s" % serial)
        m = {
            "serial": res
        }
        jm = json.dumps(m)
        if res is not None:
            return make_response_with_data(jm)
        else:
            return send_status_code(500)


init_flow_data = []


def get_init_data(key):
    global init_flow_data
    for i in init_flow_data:
        if i.get('interfaceName') == key:
            return i
    return {}


@common_api.route(constants.ROOT_API + "/netflow", methods=["GET"])
def api_get_net_flow():
    if request.method == "GET":
        global init_flow_data
        net = []
        with open('/proc/net/dev', 'r') as f:
            lines = f.readlines()
        tmp_flow_data = []
        for line in lines[2:]:
            con = line.split()
            interface_name = con[0].rstrip(":")
            if interface_name not in constants.interface_list:
                continue
            tmp = get_init_data(con[0].rstrip(":"))
            inflow = [int(con[1]) - tmp.get('flowIn', 0), 0][tmp.get('flowIn', None) is None]
            outflow = [int(con[9]) - tmp.get('flowOut', 0), 0][tmp.get('flowOut', None) is None]
            inflow = [inflow, 0][inflow < 0]
            outflow = [outflow, 0][outflow < 0]
            intf = dict(
                zip(
                    ('interfaceName', 'flowIn', 'flowOut'),
                    (interface_name, inflow*8, outflow*8)
                )
            )
            tmp_intf = dict(
                zip(
                    ('interfaceName', 'flowIn', 'flowOut'),
                    (interface_name, int(con[1]), int(con[9]))
                )
            )
            tmp_flow_data.append(tmp_intf)
            net.append(intf)
        init_flow_data = tmp_flow_data
        jm = json.dumps(net)
        if net is not None:
            return make_response_with_data(jm)
        else:
            return send_status_code(500)


@common_api.route(constants.ROOT_API + "/restore/conf", methods=["POST"])
def recovery_system_():
    if request.method == "POST":
        try:
            req = request.get_json(force=True)
            hasPassword = req.get("hasPassword")
            password = req.get("password")
            bakPath = req.get('bakPath')
            if not bakPath or not password or hasPassword is None or bakPath.find('.des3') <= 0:
                return make_response(success=False, msg='B01', status_code=200)
                # return send_status_code(400)

            if not os.path.isfile(bakPath):
                return make_response(success=False, msg='B02', status_code=200)

            if hasPassword == True:
                status, ungzip_file_path, del_folder = gdi.ungzip_file(bakPath.strip(), password)
            else:
                status, ungzip_file_path, del_folder = gdi.ungzip_file(bakPath.strip(), None)
            if not status:
                # password
                return make_response(success=False, msg='B07', status_code=200)
            SmallLogger.get_logger().info("recovery_system_ del_folder:%s" % del_folder)
            old_version_path = constants.VERSION_FILE_PATH
            tar_version_path = ungzip_file_path + '/version.txt'
            # old_md5 = gdi.get_md5_version_txt(old_version_path)
            # tar_md5 = gdi.get_md5_version_txt(tar_version_path)
            old_md5 = version_service.get_version_master(old_version_path)
            tar_md5 = version_service.get_version_master(tar_version_path)
            SmallLogger.get_logger().info("get restore old and tar version %s:%s" % (old_md5, tar_md5))
            if not old_md5 or not tar_md5 or not old_md5 == tar_md5:
                return make_response(success=False, msg='B03', status_code=200)
            db_sql_path = ungzip_file_path + '/' + 'backup_db.sql'
            res_db = gdi.recovery_db(db_sql_path)
            if not res_db:
                return make_response(success=False, msg='B04', status_code=200)
            result = system_service.factory_recovery(ungzip_file_path)
            # os.system('rm -rf %s' % del_folder)
            if result:
                return make_response(success=True, msg='A00', status_code=200)
            else:
                return make_response(success=False, msg='B06', status_code=200)

        except:
            SmallLogger.get_logger().info(traceback.format_exc())
            return make_response(success=False, msg='B05', status_code=200)


@common_api.route(constants.ROOT_API + "/portstate", methods=['POST'])
def check_port_api():
    if request.method == "POST":
        try:
            req = request.get_json(force=True)
            port = req.get("port")
            res = system_service.do_check_port_state(port)
            m = {
                "service": res
            }
            res_json = json.dumps(m)
            # print "checkportres########################## %s" % res_json
            return make_response_with_data(result=res_json)
        except Exception:
            SmallLogger.get_logger().info(traceback.format_exc())
            return make_response(success=False, status_code=200)


@common_api.route(constants.ROOT_API + "/image/dpi/copy", methods=["POST"])
def copy_dpi_image():
    if request.method == 'POST':
        req = request.get_json(force=True)
        path = req.get("path")
        result = system_service.copy_dpi_image(path)
        return make_response_with_data(result)


@common_api.route(constants.ROOT_API + "/nginx/restart", methods=["POST"])
def nginx_restart():
    if request.method == 'POST':
        # req = request.get_json(force=True)
        cmd = "nginx -s stop && nginx"
        result, msg = system_service.restart_nginx(cmd)
        if result is True:
            res = "true"
            status_code = 200
        else:
            res = "false"
            status_code = 500
        m = {
            "success": res,
            "errorCause": msg
        }
        jm = json.dumps(m)
        return make_response_with_data(result=jm, status_code=status_code)


@common_api.route(constants.ROOT_API + "/upgrade_console", methods=["POST"])
def upgrade_console():
    if request.method == 'POST':
        req = request.get_json(force=True)
        result = system_service.system_upgrade(req.get("script"))
        if result:
            return send_status_code(200)
        return send_status_code(500)


@common_api.route(constants.ROOT_API + "/restart/zebra", methods=["GET"])
def restart_zebra():
    if request.method == 'GET':
        os.system("killall -9  zebra")
        return send_status_code(200)


@common_api.route(constants.ROOT_API + "/config/register", methods=["GET","POST"])
def config_register():
    if request.method == "POST":
        request_data = request.get_json(force=True)
        result = system_service.system_register(request_data)
        if result.get("status") is True:
            system_service.write_register_status(constants.started_status)
        else:
            system_service.write_register_status(constants.error_started_status)
        return make_response_with_data(json.dumps(result))
    elif request.method == "GET":
        soc_server_info = system_service.read_soc_server_ip()
        return make_response_with_data(json.dumps(soc_server_info))

@common_api.route(constants.ROOT_API + "/hostfile", methods=["GET", "POST", "DELETE", "PUT"])
def hostfile_api():
    if request.method == "GET":
        res = network_service.get_remote_os_ip_hostname()
        res_json = json.dumps(res)
        return make_response_with_data(res_json)
    elif request.method == "POST":
        req = request.get_json(force=True)
        ip = req.get("remoteMwIp")
        res = network_service.add_ip_hostname_to_hostfile(ip=ip)
        if res is True:
            return send_status_code(status_code=200)
        else:
            return send_status_code(status_code=400)
    elif request.method == "PUT":
        req = request.get_json(force=True)
        ip = req.get("remoteMwIp")
        res = network_service.edit_ip_hostname_to_hostfile(ip=ip)
        if res is True:
            return send_status_code(status_code=200)
        else:
            return send_status_code(status_code=400)
    elif request.method == "DELETE":
        res = network_service.remove_ip_hostname_from_hostfile()
        if res is True:
            return send_status_code(status_code=200)
        else:
            return send_status_code(status_code=400)


@common_api.route(constants.ROOT_API + "/sysinfo", methods=["GET"])
def api_sysinfo():
    if request.method == "GET":
        res = system_service.get_system_info()
        res_json = json.dumps(res)
        return make_response_with_data(result=res_json)
    else:
        return send_status_code(status_code=400)


@common_api.route(constants.ROOT_API + "/reboot", methods=["POST"])
def reboot():
    if request.method == "POST":
        req = request.get_json(force=True)
        second = req.get("time")
        os.system("reboot  -d " + str(second) + " &")
        return send_status_code(200)
    else:
        return send_status_code(400)


@common_api.route(constants.ROOT_API + "/poweroff", methods=["POST"])
def poweroff():
    if request.method == "POST":
        req = request.get_json(force=True)
        second = req.get("time")
        os.system("poweroff  -d " + str(second) + " &")
        return send_status_code(200)
    else:
        return send_status_code(400)


@common_api.route(constants.ROOT_API + "/bypass", methods=["POST"])
def set_bypass():
    if request.method == "POST":
        req = request.get_json(force=True)
        bypass = req.get("bypass")
        if bypass == "on" or bypass == "off":
            cmd = "/usr/bin/ly_bp_dmi " + str(bypass)
            os.system(cmd)
            return send_status_code(200)
        else:
            return send_status_code(400)
    else:
        return send_status_code(400)

@common_api.route(constants.ROOT_API + "/l2tp", methods=["GET", "POST", "DELETE", "PUT"])
def set_l2tp():
    if request.method == "POST" or request.method == "PUT":
        req = request.get_json(force=True)
        listen_addr = req.get("listen_addr")
        ip_range = req.get("ip_range")
        local_ip = req.get("local_ip")
        secrets = req.get("secrets")
        ret = l2tp_service.new_l2tp_vpn(listen_addr, ip_range, local_ip, secrets)
        if ret == True:
            return send_status_code(200)
        else:
            return send_status_code(400)
    elif request.method == "DELETE":
        if l2tp_service.stop_l2tp_daemon():
            ret = 200
        else:
            ret = 400
        return send_status_code(ret)
    else:
        ret = l2tp_service.show_l2tp_conf()
        return make_response_with_data(json.dumps(ret))

@common_api.route(constants.ROOT_API + "/l2tp/user", methods=["GET", "POST", "DELETE", "PUT"])
def l2tp_user():
    if request.method == "POST" or request.method == "PUT":
        req = request.get_json(force=True)
        user = req.get("user_name")
        passwd = req.get("password")
        users = l2tp_service.l2tp_add_user(user, passwd)
    elif request.method == "DELETE":
        req = request.get_json(force=True)
        user = req.get("user_name")
        users = l2tp_service.l2tp_del_user(user)
    elif request.method == "GET":
        users = l2tp_service.l2tp_show_users()
    else:
        return send_status_code(400)

    m = {'users': ','.join(users)}
    return make_response_with_data(json.dumps(m))

@common_api.route(constants.ROOT_API + "/ca/root", methods=["GET", "POST", "DELETE", "PUT"])
def create_del_root_ca():
    if request.method == "POST" or request.method == "PUT":
        req = request.get_json(force=True)
        country = req.get("C")
        state = req.get("ST")
        org = req.get("O")
        depart = req.get("OU")
        common_name = "root"
        email = req.get("emailAddress")
        if not all([country, state, org, common_name]):
            return make_response(success=False, msg="params error", status_code=400)

        subj="/C=" + country + "/ST=" + state + "/O=" + org
        if depart != '' and depart != None:
            subj += "/OU=" + depart
        subj += "/CN=" + common_name
        if email != '' and email != None:
            subj += "/emailAddress=" + email
        ret = ca_service.create_root_ca(subj)
        if ret == 0:
            return make_response(success=True, msg="success", status_code=200)

        return send_status_code(400)
    elif request.method == "DELETE":
        ca_service.delete_root_ca()
        return send_status_code(200)
    elif request.method == "GET":
        ca_info, clients = ca_service.show_ca_info('')
        if ca_info !='a':
            ret = {
                'root_ca': ca_info,
                'client_certs': clients
            }
            return make_response_with_data(json.dumps(ret))
        return send_status_code(400)

@common_api.route(constants.ROOT_API + "/ca/host", methods=["GET", "POST", "DELETE", "PUT"])
def create_del_host_cert():
    if request.method == "POST" or request.method == "PUT":
        req = request.get_json(force=True)
        cname = ranstr()
        country = req.get("C")
        state = req.get("ST")
        org = req.get("O")
        depart = req.get("OU")
        common_name = req.get("CN")
        email = req.get("emailAddress")
        pkcs = req.get("pkcs")

        if not all([country, state, org, common_name]):
            return make_response(success=False, msg="params error", status_code=400)

        subj="/C=" + country + "/ST=" + state + "/O=" + org
        if depart != None and depart != '':
            subj += "/OU=" + depart + "/CN=" + common_name
        else:
            subj += "/CN=" + common_name
        if email != None and email != '':
            subj += "/emailAddress=" + email

        ret, msg = ca_service.create_host_cert(cname, subj)
        if ret != 0:
            return make_response(success=False, msg=msg, status_code=400)
        else:
            host_info = ca_service.show_ca_info(cname + "Cert.pem")
            if host_info == 'a':
                return send_status_code(400)
            ret = {
                'host_cert': host_info,
            }
            return make_response_with_data(json.dumps(ret))
    elif request.method == "DELETE":
        req = request.get_json(force=True)
        cname = req.get("name")
        ca_service.del_host_cert(cname)
        return send_status_code(200)
    elif request.method == "GET":
        req = request.get_json(force=True)
        cname = req.get("name")
        host_info = ca_service.show_ca_info(cname)
        ret = {
                'host_cert': host_info,
        }
        return make_response_with_data(json.dumps(ret))
@common_api.route(constants.ROOT_API + "/ca/show/all", methods=["GET"])
def show_all_cert():
    ca = ca_service.show_ca_info('')
    clients = ca_service.show_client_info()
    ret = {
            'client': clients
    }
    return make_response_with_data(json.dumps(ret))

@common_api.route(constants.ROOT_API + "/upload/cert", methods=["POST"])
def upload_p12_file():
    if request.method == "POST":
        req = request.get_json(force=True)
        cert_path = req.get("cert_path")
        if os.path.isfile(cert_path):
            ca_service.upload_cert(cert_path)
            return send_status_code(200)
        else:
            SmallLogger.get_logger().info(cert_path + " not exist")
            return send_status_code(400)

@common_api.route(constants.ROOT_API + "/download/cert", methods=["POST"])
def download_cert():
    if request.method == "POST":
        req = request.get_json(force=True)
        filename = req.get("name")
        download_path = req.get("cert_path")
        if filename == "cacert.pem":
            path = "/etc/ipsec.d/demoCA/"
        elif filename == "serverCert.pem":
            path = "/etc/ipsec.d/certs/"
        else:
            path = "/etc/ipsec.d/private"
        cert_file = path + "/" + filename

        SmallLogger.get_logger().info(cert_file)
        if os.path.exists(cert_file):
            try:
                shutil.copy(cert_file, download_path)
                return send_status_code(200)
            except:
                SmallLogger.get_logger().info(traceback.format_exc())
        else:
            SmallLogger.get_logger().info(download_path + " not exist")
    return send_status_code(400)

@common_api.route(constants.ROOT_API + "/ipsec", methods=["GET", "POST", "DELETE", "PUT"])
def ipsec_vpn():
    if request.method == "POST" :
        req = request.get_json(force=True)
        conn_name = req.get('conn_name')
        conn_type = req.get('conn_type')
        conn_info = req.get('conn_info')
        secret_str = req.get('secret')
        if '_psk' in conn_type:
            if secret_str == None  or secret_str == '':
                return make_response(success=False, msg="secret is needed", status_code=400)
        ret = ipsec_service.new_ipsec_conns(conn_type, conn_name, conn_info)
    if request.method == "DELETE":
        req = request.get_json(force=True)
        conn_name = req.get('conn_name')
        ret = ipsec_service.del_vpn_conns(conn_name)

@common_api.route(constants.ROOT_API + "/ipsec/status", methods=["GET", "POST", "DELETE"])
def ipsec_status():
    pass
