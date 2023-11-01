set -e
if [ ! -f cl/PKVM_USER ]
then
  echo 'Please copy cl/DEFAULT_PKVM_USER cl/PKVM_USER' && false
fi

PKVM_USER=$(cat cl/PKVM_USER)

ssh -t ${PKVM_USER}@localhost -p8022 'sudo ./lkvm-static run -k Image'