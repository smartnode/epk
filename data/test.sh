#!/bin/bash

INPUT_FILE=sample.bin
SIGNATURE_FILE=sample.sgn
PRIVATE_KEY_FILE=EPK-PRIVATE-KEY.pem
CURRENT_PATH=$PWD
HASH_ALGO=sha512
SYSFS_PATH=/sys/kernel/epk/verify

/usr/bin/openssl dgst -${HASH_ALGO} -sign ${PRIVATE_KEY_FILE} -out ${SIGNATURE_FILE} ${INPUT_FILE}

DATA="${HASH_ALGO} ${CURRENT_PATH}/${INPUT_FILE} ${CURRENT_PATH}/${SIGNATURE_FILE}"
echo "Set Data: ${DATA}"
echo "${DATA}" >> ${SYSFS_PATH}

echo "Get Result: "
cat ${SYSFS_PATH}

