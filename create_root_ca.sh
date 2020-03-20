#!/bin/bash

CA_PASSWD=admin@123!@#
Init_ca() {
    cd /etc/ipsec.d
    rm -rf ./demoCA
    mkdir demoCA
    mkdir demoCA/newcerts
    mkdir demoCA/private
    touch demoCA/index.txt
    echo "01" >> demoCA/serial
}


create_root_ca()  {
    openssl req -x509 -days 3650 -newkey rsa:2048 -passout pass:$CA_PASSWD -keyout /etc/ipsec.d/private/caKey.pem -out /etc/ipsec.d/cacerts/caCert.pem -subj $1
    return $?
}

create_host_cert() {
    openssl req  -newkey rsa:2048 -passout pass:$2 -keyout /etc/ipsec.d/private/$1Key.pem -out /etc/ipsec.d/private/$1Req.pem -subj $3
    openssl rsa -passin pass:$2 -in /etc/ipsec.d/private/$1Key.pem -out /etc/ipsec.d/private/$1Key.pem.openswan
    openssl ca -batch -passin pass:$CA_PASSWD -in /etc/ipsec.d/private/$1Req.pem -days 730 -out /etc/ipsec.d/certs/$1Cert.pem -notext -cert /etc/ipsec.d/cacerts/caCert.pem -keyfile /etc/ipsec.d/private/caKey.pem
    openssl pkcs12 -passin pass:$2 -export -in /etc/ipsec.d/certs/$1Cert.pem -inkey /etc/ipsec.d/private/$1Key.pem -certfile /etc/ipsec.d/cacerts/caCert.pem -out $1.p12


}

#----------------main-----------------
if [ "$1" == "create_root_ca" ]; then
    Init_ca
    create_root_ca $2
    create_host_cert "server" $CA_PASSWD $2
elif [ "$1" == "create_host_cert" ];then
    create_host_cert $2 $3 $4
fi
