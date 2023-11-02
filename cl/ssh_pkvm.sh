set -e

read -p "login: " PKVM_USER

ssh -t ${PKVM_USER}@localhost -p8022 'sudo ./lkvm-static run -k Image'