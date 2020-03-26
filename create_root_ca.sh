#!/bin/bash

CA_PASSWD="admin@123!@#"
HOST_PASSWD="qaz123!@#"
Init_ca() {
    rm -rf ./demoCA
    mkdir demoCA
    mkdir demoCA/newcerts
    mkdir demoCA/private
    touch demoCA/index.txt
    echo "01" >> demoCA/serial
}


create_root_ca()  {
    openssl req -x509 -days 3650 -newkey rsa:2048 -passout pass:$CA_PASSWD -keyout /etc/ipsec.d/demoCA/private/cakey.pem -out /etc/ipsec.d/demoCA/cacert.pem -subj $1
#    if [ $? -eq 0 ]; then
#        openssl req  -newkey rsa:2048 -passout pass:$HOST_PASSWD -keyout /etc/ipsec.d/private/serverKey.pem -out /etc/ipsec.d/private/serverReq.pem -subj $1
#        openssl rsa -passin pass:$HOST_PASSWD -in /etc/ipsec.d/private/serverKey.pem -out /etc/ipsec.d/private/serverKey.pem.openswan
#        tmp=`mktemp`
#        cat > $tmp << END
#            basicConstraints=CA:FALSE
#            nsComment="OpenSSL Generated Certificate"
#            subjectKeyIdentifier=hash
#            authorityKeyIdentifier=keyid,issuer:always
#            extendedKeyUsage = serverAuth
#END
#        openssl ca -md sha256 -days 730 -batch -notext -passin pass:$CA_PASSWD -in /etc/ipsec.d/private/serverReq.pem -out /etc/ipsec.d/certs/serverCert.pem -extfile $tmp
#        ret=$?
#        unlink $tmp
#        return $ret
#    fi
    return $?
}

del_root_ca() {
    rm -rf /etc/ipsec.d/demoCA/
    rm -rf /etc/ipsec.d/certs/*.pem
    rm -rf /etc/ipsec.d/private/*.pem
    rm -rf /etc/ipsec.d/private/*.pem.openswan
    rm -rf /etc/ipsec.d/private/*.p12
    return 0
}

create_host_cert() {
    openssl req  -newkey rsa:2048 -passout pass:$2 -keyout /etc/ipsec.d/private/$1Key.pem -out /etc/ipsec.d/private/$1Req.pem -subj $3
    openssl rsa -passin pass:$2 -in /etc/ipsec.d/private/$1Key.pem -out /etc/ipsec.d/private/$1Key.pem.openswan
    tmp=`mktemp`
    cat > $tmp << END
        basicConstraints=CA:FALSE
        nsComment="OpenSSL Generated Certificate"
        subjectKeyIdentifier=hash
        authorityKeyIdentifier=keyid,issuer:always
        extendedKeyUsage=clientAuth
END
    openssl ca -md sha256 -days 730 -batch -notext -passin pass:$CA_PASSWD -in /etc/ipsec.d/private/$1Req.pem -out /etc/ipsec.d/certs/$1Cert.pem -extfile $tmp
    res=$?
    unlink $tmp
    if [ $res -eq 0 ] &&  [ $# -eq 4 ]; then
        openssl pkcs12 -passin pass:$CA_PASSWD -passout pass:$4 -export -in /etc/ipsec.d/certs/$1Cert.pem -inkey /etc/ipsec.d/private/$1Key.pem.openswan -certfile /etc/ipsec.d/demoCA/cacert.pem -out /etc/ipsec.d/private/$1Cert.p12
    fi
    if [ $res -ne 0 ];then
        del_host_cert $1
    fi
    return $res
}

del_host_cert() {
    cname=$1
    rm -rf /etc/ipsec.d/certs/$1Cert.pem
    rm -rf /etc/ipsec.d/private/$1*
    return
}
#----------------main-----------------
subj=$2
cname=$3
passout=$4          # pkcs12 passwd

cd /etc/ipsec.d
if [ "$1" == "create_root_ca" ]; then
    Init_ca
    create_root_ca $2
    if [ $? != 0 ]; then
        exit 100
    fi
elif [ "$1" == "create_host_cert" ];then
    create_host_cert $cname $HOST_PASSWD $subj $passout
elif [ "$1" == "del_root_ca" ]; then
    del_root_ca
elif [ "$1" == "del_host_cert" ]; then
    del_host_cert $2
fi
