set -e

read -p "login: " PKVM_USER

# copy in lkvm and unwrap it
scp -P 8022 cl/lkvm/lkvm-static.zst ${PKVM_USER}@localhost:/home/${PKVM_USER}/
ssh ${PKVM_USER}@localhost -p8022 'zstd --decompress lkvm-static.zst && chmod +x ./lkvm-static'

# copy in a kernel Image
scp -P 8022 arch/arm64/boot/Image ${PKVM_USER}@localhost:/home/${PKVM_USER}/

# copy in kvmtest and unwrap it
scp -P 8022 cl/kvmtest/kvmtest.zst ${PKVM_USER}@localhost:/home/${PKVM_USER}/
ssh ${PKVM_USER}@localhost -p8022 'zstd --decompress kvmtest.zst && chmod +x ./kvmtest'