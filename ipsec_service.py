#!/bin/python
import os
import subprocess
from ipsecparse import loads

def new_ipsec_conns(vname, vtype, vpn_conns, secrets=None):
    conf = loads(open('/etc/ipsec.conf').read())
    this_conf = loads('')
    if vtype == "roadwarriors_rsa":
        temp_conf=loads(open('/etc/ipsec.d/conns/roadwarriors.conf').read())
        roadw = temp_conf['conn', 'roadwarriors_rsa']
        roadw.update(vpn_conns)
        roadw['auto'] = 'add'
        conf['conn', vname] = roadw
        this_conf['conn', 'roadwarriors_rsa'] = roadw

    elif vtype == 'roadwarriors_psk':
        temp_conf=loads(open('/etc/ipsec.d/conns/roadwarriors.conf').read())
        roadw = temp_conf['conn', 'roadwarriors_psk']
        roadw.update(vpn_conns)
        roadw['auto'] = 'add'
        conf['conn', vname] = roadw
        this_conf['conn', 'roadwarriors_rsa'] = roadw

    elif vtype == 'net_to_net_psk':
        temp_conf=loads(open('/etc/ipsec.d/conns/net_to_net.conf').read())
        nton = temp_conf['conn', 'net_to_net_psk']
        nton.update(vpn_conns)

        conf['conn', vname] = nton
        this_conf['conn', vname] = nton

    elif vtype == 'net_to_net_rsa':
        temp_conf=loads(open('/etc/ipsec.d/conns/net_to_net.conf').read())
        nton = temp_conf['conn', 'net_to_net_rsa']
        nton.update(vpn_conns)

        conf['conn', vpn_conns.name] = nton
        this_conf['conn', vpn_conns.name] = nton

    try:
        conf_str = conf.dumps()
    except:
        return -1, 'Add conns failed'

    debug_print(conf.dumps())
    with open('/etc/ipsec.conf', 'w') as fd:
        fd.write(conf_str)

    shcmd = "/usr/local/sbin/ipsec auto --add " + vname
    ret=subprocess.Popen(shcmd, shell=True, stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    ret_str = ret.stdout.read()
    if "adding connection:" in ret_str:
        conn_info = this_conf.dumps()
        ret_code = 0
    else:
        del_vpn_conns(vname)
        conn_info = ret_str
        ret_code = -1
    debug_print (conn_info)
    return ret_code, conn_info

def del_vpn_conns(vname):
    conf = loads(open('/etc/ipsec.conf').read())
    try:
        conns_to_del = conf['conn', vname]
    except:
        pass
    del conf['conn', vname]

    try:
        conf_str = conf.dumps()
    except:
        return -1, 'del conns failed'

    with open('/etc/ipsec.conf', 'w') as fd:
        fd.write(conf_str)
    return True

def check_conns_info(vpn_conns):
    for key, value in vpn_conns.items():
        if value == None or value == '':
            del vpn_conns[key]
    return vpn_conns

def debug_print(obj):
    if __name__ == '__main__':
        print obj
    else:
        pass

if __name__ == '__main__':
    import sys
    import unittest
#    new_ipsec_conns('test', 'roadwarriors_psk', {"left":'192.168.1.110', 'leftsubnet': '172.168.1.0/24', 'authby': 'secret', 'type': 'tunnel'}, "admin@123")
#    new_ipsec_conns('test', 'roadwarriors_rsa', {"left":'192.168.1.110', 'leftsubnet': '172.168.1.0/24', 'authby': 'secret', 'type': 'tunnel'}, "admin@123")
    new_ipsec_conns('test', 'net_to_net_psk', {"left":'192.168.1.110', 'leftsubnet': '172.168.1.0/24', 'right': '10.13.61.11', 'rightsubnet': '172.168.2.0/24','authby': 'secret', 'type': 'tunnel'}, "admin@123")

