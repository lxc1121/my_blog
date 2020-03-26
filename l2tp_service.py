import subprocess
from ipsecparse import loads
from backports.configparser import ConfigParser

def config_ipsec_secret(listen_addr, secrets):
    shcmd = "sed -i '/" + secrets + "/d' /etc/ipsec.secrets"
    ret = excute_cmd(shcmd)
    ret.stdout.read()
    pskstr = listen_addr + ' %any : PSK "' + secrets + '"\n'
    with open('/etc/ipsec.secrets', 'a') as fd:
        fd.write(pskstr)
    return

def new_l2tp_vpn(listen_addr, ip_range, local_ip, secrets):
    conf = loads(open('/etc/ipsec.d/conns/l2tp.conf').read())
    l2tp = conf['conn', 'L2TP-PSK-noNAT']
    l2tp['left'] = listen_addr
    with open('/etc/ipsec.d/conns/l2tp.conf', 'w') as fd:
        fd.write(conf.dumps())
    shcmd = "/usr/local/sbin/ipsec auto --add L2TP-PSK-NAT"
    ret = excute_cmd(shcmd)

    l2tp_conf = ConfigParser()
    l2tp_conf.read('/etc/xl2tpd/xl2tpd.conf')

    c_global = l2tp_conf['global']
    c_global['listen-addr'] = listen_addr

    lns = l2tp_conf['lns default']
    lns['ip range'] = ip_range
    lns['local ip'] = local_ip

    with open('/etc/xl2tpd/xl2tpd.conf', 'w') as fd:
        l2tp_conf.write(fd)

    config_ipsec_secret(listen_addr, secrets)
    shcmd = "/etc/init.d/xl2tpd restart"
    ret = excute_cmd(shcmd)
    shret=ret.wait()
    if shret == 0:
        return True
    else:
        return False

def show_l2tp_conf():
    l2tp_conf = ConfigParser()
    l2tp_conf.read('/etc/xl2tpd/xl2tpd.conf')
    c_global = l2tp_conf['global']
    lns = l2tp_conf['lns default']
    return {
            "listen_addr" : c_global['listen-addr'],
            "ip_range" : lns['ip range'],
            "local_ip" : lns['local ip'],
            "status" : get_l2tpd_status()
        }

def stop_l2tp_daemon():
    shcmd = "/etc/init.d/xl2tpd stop"
    ret = excute_cmd(shcmd)
    shret=ret.wait()
    if shret == 0:
        return True
    else:
        return False
def get_l2tpd_status():
    shcmd="ps aux |grep xl2tpd |grep -v grep"
    ret = excute_cmd(shcmd)
    shret = ret.stdout.read()
    if 'xl2tpd' in shret:
        return True
    else:
        return False

def l2tp_show_users():
    users = []
    with open('/etc/ppp/chap-secrets', 'r') as fd:
        lines = fd.readlines()
        for line in lines:
            if line[0] == '#' or line[0] == '\n':
                continue
            else:
                users.append(line.split()[0])
    return users

def l2tp_del_user(users):
    for user in users.split(','):
        shcmd = "sed -i '/" + user + "\ /d' /etc/ppp/chap-secrets"
        ret = excute_cmd(shcmd)
    ret.stdout.read()
    return l2tp_show_users()

def l2tp_add_user(user, passwd):
    l2tp_del_user(user)
    user_str = user + '         *       ' + passwd + '      *\n'
    with open('/etc/ppp/chap-secrets', 'a') as fd:
        fd.write(user_str)
    return l2tp_show_users()

def excute_cmd(cmd):
    return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
