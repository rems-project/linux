set -e
if [ ! -f cl/PKVM_USER ]
then
  echo 'Please copy cl/DEFAULT_PKVM_USER cl/PKVM_USER' && false
fi

PKVM_USER="$(cat cl/PKVM_USER)"

# copy in lkvm
scp -P 8022 cl/lkvm/lkvm-static.zst ${PKVM_USER}@localhost:/home/${PKVM_USER}/

# unwrap it
ssh ${PKVM_USER}@localhost -p8022 'zstd --decompress lkvm-static.zst && chmod +x ./lkvm-static'

# copy in a kernel Image
scp -P 8022 arch/arm64/boot/Image ${PKVM_USER}@localhost:/home/${PKVM_USER}/