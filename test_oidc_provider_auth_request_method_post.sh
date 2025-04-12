#!/bin/bash

if [ -f /etc/os-release ]; then
    . /etc/os-release
    VER_MAJOR=$(echo $VERSION_ID|cut -f1 -d.)
    VER_MINOR=$(echo $VERSION_ID|cut -f2 -d.)
fi

if [ "$ID" = "rhel" -a $VER_MAJOR -eq 8 ]; then
    PODMANNIC="cni-podman0"
else
    PODMANNIC="podman0"
fi

# Install wireshark
dnf -y install wireshark

# Set OIDCProviderAuthRequestMethod to POST in mod_auth_openidc config
echo "OIDCProviderAuthRequestMethod POST" \
    >> /etc/httpd/conf.d/openidc_example_app_oidc_keycloak_master.conf
systemctl restart httpd

# Set SSLKEYLOGFILE environment variable to record keys needed to decrypt pcap
export SSLKEYLOGFILE=/tmp/sslkey.log
rm -f $SSLKEYLOGFILE

# Start sniffing
tshark -q -w /tmp/test_ssl_oidc_leak.pcapng -s 0 -i lo -i $PODMANNIC &
TPID=$(pidof tshark)

# slight pause to allow tshart to start capture
sleep 1

# Run curl to gather data
curl https://$(hostname):60443/openidc_root/private/index.html

# pause for tshark
sleep 1

# Stop tshark process
kill $TPID

# pause for tshark to complete writing capture file
sleep 1

# run decrypt and fail if tshark fails
set -e
tshark -s 0 \
    -r /tmp/test_ssl_oidc_leak.pcapng \
    -o tls.keylog_file:/tmp/sslkey.log \
    -o tls.desegment_ssl_records:TRUE \
    -o tls.desegment_ssl_application_data:TRUE \
    -T fields -e xml.cdata -e http.file_data > /dev/null 
set +e

# decrypt TLS data and check if secure content leaked
tshark -s 0 \
    -r /tmp/test_ssl_oidc_leak.pcapng \
    -o tls.keylog_file:/tmp/sslkey.log \
    -o tls.desegment_ssl_records:TRUE \
    -o tls.desegment_ssl_application_data:TRUE \
    -V | grep -B1 "there...from SP"| grep Hello -A1

# Using fields is inconsistent and difficult to do with older versions 
# of wireshark.   Need a better way to decode file_data.
#    -T fields -e xml.cdata -e http.file_data | grep "Hello there...from SP"

if [ $? -eq 0 ]; then
    echo "Leak found...test failed"
    exit 1
else
    echo "Leak not found...test passed"
    exit 0
fi
