#!/bin/bash

PKEY_HEADER_FILE=epk-public-key.h

openssl req -config key.config \
    -new -nodes -x509 -newkey rsa:4096 -sha512 \
    -keyout EPK-PRIVATE-KEY.pem \
    -out EPK-X509-CERTIFICATE.pem \
    -days 365000
if [ $? -ne 0 ]; then
    echo "Failed to generate key pair"
    exit 1
fi

openssl x509 -outform der -in EPK-X509-CERTIFICATE.pem \
    -out EPK-X509-CERTIFICATE.der
if [ $? -ne 0 ]; then
    echo "Failed to convert certificate to DER format"
    exit 1
fi

cat << EOF > ${PKEY_HEADER_FILE}
/*
 * Copyright (C) 2022 Elmurod Talipov <elmurod.talipov@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 *
 */

#ifndef __EPK_PUBLIC_KEY_H__
#define __EPK_PUBLIC_KEY_H__

EOF

xxd -i EPK-X509-CERTIFICATE.der >> ${PKEY_HEADER_FILE}
sed -i "s/EPK_X509_CERTIFICATE_der_len/EPK_X509_CERTIFICATE_LEN/g" ${PKEY_HEADER_FILE}
sed -i "s/EPK_X509_CERTIFICATE_der/EPK_X509_CERTIFICATE_DATA/g" ${PKEY_HEADER_FILE}

echo "" >> ${PKEY_HEADER_FILE}
echo "#endif" >> ${PKEY_HEADER_FILE}
echo "" >> ${PKEY_HEADER_FILE}

mv -f ${PKEY_HEADER_FILE} ../
