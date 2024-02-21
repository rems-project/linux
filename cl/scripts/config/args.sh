#/usr/bin/env sh

set -e

usage() {
cat << EOF
Usage: $0 [-d]

-h, --help      Prints this text
-d, --disable   Disable config options
EOF
}

options=$(getopt -al "disable,help" -o "dh" -- "$@")

eval set -- "$options"

ENABLE='./scripts/config -e'
DISABLE='./scripts/config -d'
SET='./scripts/config --set-val'

ENABLE='-e'
DISABLE='-d'

while true
do
case "$1" in
-h|--help)
    usage
    exit 0
    ;;
-d|--disable)
    ENABLE='-d'
    DISABLE='-e'
    ;;
--)
    shift
    break;;
esac
shift
done