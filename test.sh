#! /bin/sh

set -e

TMPDIR=${TMPDIR:-/tmp}
PIKNIK="./piknik -config ${TMPDIR}/piknik-test.toml"

cat > "${TMPDIR}/piknik-test.toml" <<EOT
Connect   = "127.0.0.1:8076"
Listen    = "127.0.0.1:8076"
Psk       = "627ea393638048bc0d5a7554ab58e41e5601e2f4975a214dfc53b500be462a9a"
SignPk    = "c2e46983e667a37d7d8d69679f40f3a05eb8086337693d91dcaf8546d39ddb5e"
SignSk    = "7599dad4726247d301c00ce0dc0dbfb9144fa958b4e9db30209a8f9d840ac9ca"
EncryptSk = "f313e1fd4ad5fee8841d40ca3d54e14041eb05bf7f4888ad8c800ceb61942db6"
EOT

go build
$PIKNIK -server &
pid=$!
sleep 2
dd if=/dev/urandom of=/tmp/pi bs=1000 count=1
$PIKNIK -copy < /tmp/pi
$PIKNIK -paste > /tmp/pi2
cmp /tmp/pi /tmp/pi2
$PIKNIK | $PIKNIK -copy
$PIKNIK -move > /tmp/pi2
cmp /tmp/pi /tmp/pi2
$PIKNIK && exit 1
kill $pid

echo
echo 'Success!'
echo
