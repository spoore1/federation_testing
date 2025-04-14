#!/bin/bash

set -x

AUTHDIR=${1:-""}
KHCI_SERVERURL="https://$(hostname):8443${AUTHDIR}"
echo "Running tests with AUTHDIR=${AUTHDIR}"
echo "Running tests with KHCI_SERVERURL=${KHCI_SERVERURL}"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    VER_MAJOR=$(echo $VERSION_ID|cut -f1 -d.)
    VER_MINOR=$(echo $VERSION_ID|cut -f2 -d.)
fi

if [ "$ID" = "rhel" -a $VER_MAJOR -eq 8 ]; then
    AUTHDIR="/auth"
    KHCI_SERVERURL="https://$(hostname):8443"
    echo "Resetting AUTHDIR to ${AUTHDIR} for RHEL 8"
    echo "Resetting KHCI_SERVERURL to ${KHCI_SERVERURL} for RHEL 8"
fi

if [ "$ID" = "rhel" -a $VER_MAJOR -eq 9 -a $VER_MINOR -le 5 ]; then
    AUTHDIR="/auth"
    KHCI_SERVERURL="https://$(hostname):8443"
    echo "Resetting AUTHDIR to ${AUTHDIR} for RHEL 9.5 and earlier"
    echo "Resetting KHCI_SERVERURL to ${KHCI_SERVERURL} for RHEL 9.5 and earlier"
fi

################

echo Secret123 | \
keycloak-httpd-client-install   \
    --client-originate-method registration \
    --client-hostname $(hostname) \
    --keycloak-server-url ${KHCI_SERVERURL} \
    --keycloak-admin-username admin \
    --keycloak-admin-password-file - \
    --app-name mellon_example_app \
    --keycloak-realm master \
    --location-root "/mellon_root" \
    --client-https-port 60443 \
    --protected-locations "/mellon_root/private" \
    --force

################

semanage port -a -t http_port_t -p tcp 60443 || echo "semanage port 60443 already added"
setsebool httpd_can_network_connect=on || echo "setsebool httpd_can_network_connect=on already"

systemctl restart httpd


################
# setup for mellon-diagnostics test

# Just exit if mod_auth_mellon-diagnostics can't be installed,
# at the moment it's not present in any of the repos
# (see RCM-59421)
rpm -q mod_auth_mellon-diagnostics || \
    dnf -y install mod_auth_mellon-diagnostics || \
    exit 0

rm -f /var/log/httpd/mellon_diagnostics

cat > /etc/httpd/conf.d/mellon_diag.conf <<EOF
MellonDiagnosticsEnable on
EOF

# This just rewrites the contents so we should either make the test smarter and
# revert the contents or keep this test last
echo "LoadModule auth_mellon_module modules/mod_auth_mellon-diagnostics.so" > /etc/httpd/conf.modules.d/10-auth_mellon.conf

systemctl restart httpd || exit 1
################

# Enable ECP Flow for client in Keycloak

kcadm="podman exec keycloak /opt/keycloak/bin/kcadm.sh"

$kcadm config credentials --server https://$(hostname):8443/auth/ \
        --realm master --user admin --password Secret123

CLIENTID="https://$(hostname):60443/mellon_root/mellon/metadata"
ID=$($kcadm get clients| jq -r ".[]|select(.clientId==\"$CLIENTID\").id")

$kcadm update clients/$ID -r master -s 'attributes={"saml.allow.ecp.flow":"true"}'

# Run test
sleep 10

py.test-3 --idp-realm master \
          --idp-url https://$(hostname):8443${AUTHDIR} \
          --sp-url https://$(hostname):60443/mellon_root \
          --username testuser --password Secret123 \
          --url https://$(hostname):60443/mellon_root/private \
          --logout-url=https://$(hostname):60443/mellon_root/private \
          --info-url=https://$(hostname):60443/mellon_root/private/static \
          --nested-protected-url=https://$(hostname):60443/mellon_root/private/static/private_static \
          --bad-logout-redirect-url=http:www.redhat.com,'\/redhat.com','\//redhat.com','\///redhat.com' \
          --junit-xml=result_mellon.xml \
          test_mellon.py
rv=$?
if [ $rv -ne 0 ]; then
    echo "Mellon test failed"
    exit 1
fi
