#!/bin/python
import os, sys
import subprocess

if '__main__' == __name__:
    cur_abs_path = os.path.dirname(os.path.realpath(__file__))
    sys.path.append(cur_abs_path+'/../')

from common import constants
from common.small_logger import SmallLogger
import traceback
if '__main__' == __name__:
    pwd=os.getcwd()
    constants.ca_script=pwd + '/script/create_root_ca.sh'
os.chdir("/etc/ipsec.d")

CA_PASSWD="admin@123!@#"
def create_root_ca(subj,days=3650):
    shcmd=constants.ca_script + " create_root_ca " + subj
    ret = excute_cmd(shcmd)
    stdout,stderr = ret.communicate()
    if '__main__' == __name__:
        print stdout
    SmallLogger.get_logger().info(stdout)
    return ret.returncode

def create_host_cert(cname, subj, pkcs="!admin@123", days=730):
    shcmd=constants.ca_script + " create_host_cert " + subj + ' ' + cname + ' ' + pkcs
    ret = excute_cmd(shcmd)
    stdout,stderr = ret.communicate()
    if '__main__' == __name__:
        print stdout

    SmallLogger.get_logger().info(stdout)
    return ret.returncode, stdout

def show_ca_info(cname):
    if cname == '':
        ca_info={}
        if os.path.exists('/etc/ipsec.d/demoCA/cacert.pem'):
            shcmd = "openssl x509 -in /etc/ipsec.d/demoCA/cacert.pem -text -noout |grep Subject:"
            try:
                ret = excute_cmd(shcmd)
                line = excute_cmd(shcmd).stdout.readline()
                if "Subject:" not in line:
                    SmallLogger.get_logger().info(line)
                    return 'a', []
                line = line[17:]
                line = line.replace('/', ', ')
                ca_info = dict(l.split('=') for l in line.split(', '))
                ca_info['name'] = "cacert.pem"
            except:
                SmallLogger.get_logger().info(traceback.format_exc())
                return 'a', {}
        return ca_info, show_client_info()
    else:
        host_info = {}
        cert_path = "/etc/ipsec.d/certs/" + cname
        SmallLogger.get_logger().info(cert_path)
        if os.path.exists(cert_path):
            shcmd = "openssl x509 -in " + cert_path + " -text -noout |grep Subject:"
            line = excute_cmd(shcmd).stdout.readline()

            if "Subject:" not in line:
                SmallLogger.get_logger().info(line)
                return 'a', []

            line = line[17:]
            line = line.replace('/', ', ')
            host_info = dict(l.split('=') for l in line.split(', '))
            host_info['name'] = cname
        return host_info

def show_client_info():
    clients = []
    certs = os.listdir('/etc/ipsec.d/certs')
    for name in certs:
        if "Cert.pem" in name or "cert.pem" in name:
            clients.append(show_ca_info(name))
    return clients

def delete_root_ca():
    shcmd = constants.ca_script + " del_root_ca"
    ret = excute_cmd(shcmd)
    return True

def del_host_cert(cname):
    if "Cert.pem" in cname or "cert.pem" in cname:
        cname  = cname[:-8]
    shcmd = constants.ca_script + " del_host_cert " + cname
    SmallLogger.get_logger().info(shcmd)
    ret = excute_cmd(shcmd)
    return True

def upload_cert(cert_path):
    filename = os.path.basename(cert_path)
    SmallLogger.get_logger().info("Upload cert file" + filename)
    if filename == "cacert.pem":
        os.system("mkdir /etc/ipsec.d/demoCA/")
        shcmd = "cp " + cert_path + " /etc/ipsec.d/demoCA/"
        SmallLogger.get_logger().info(shcmd)
    if filename[-8:] == "Cert.pem" or filename[-8:] == "cert.pem":
        shcmd = "cp " + cert_path + " /etc/ipsec.d/certs/"
    elif filename[-4:] == ".p12":
        shcmd = "cp " + cert_path + " /etc/ipsec.d/private/"
    elif filename[-4:] == ".pem":
        shcmd = "cp " + cert_path + " /etc/ipsec.d/certs/" + filename[:-4] + "cert.pem"
    else:
        pass
    ret = excute_cmd(shcmd)
    ret.stdout.read()
    if filename[-4:] == ".p12":
        proc_p12_file(filename)
    return True

def proc_p12_file(filename):
    p12_path = "/etc/ipsec.d/private/" + filename
    cert_path = "/etc/ipsec.d/certs/" + filename.replace('Cert.p12', 'Cert.pem')
    key_path = "/etc/ipsec.d/private/" + filename.replace('Cert.p12', 'Key.pem')
    if os.path.exists(p12_path) == False:
        return
    shcmd = "openssl pkcs12 -passin pass:!admin@123 -clcerts -nokeys -out " + cert_path + " -in " + p12_path
    ret = excute_cmd(shcmd)
    stdout,stderr = ret.communicate()
    if '__main__' == __name__:
        print stdout
    SmallLogger.get_logger().info(stdout)
    shcmd = "openssl pkcs12 -passin pass:!admin@123 -nocerts -nodes -out " +  key_path + " -in " + p12_path
    ret = excute_cmd(shcmd)
    stdout,stderr = ret.communicate()
    if '__main__' == __name__:
        print stdout
    SmallLogger.get_logger().info(stdout)
    return True



def excute_cmd(cmd):
    return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,stderr=subprocess.STDOUT)

if '__main__' == __name__:
    create_root_ca("/C=CN/ST=BJ/O=gotech/CN=gotech")
    create_host_cert("zhangsan", "/C=CN/ST=BJ/O=gotech/CN=zhangsan", "123456")
