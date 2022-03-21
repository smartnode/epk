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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <crypto/hash.h>
#include <crypto/public_key.h>
#include <linux/key.h>
#include <linux/cred.h>
#include <linux/fs.h>

#include "epk-public-key.h"

#define XSTR(s) STR(s)
#define STR(s) #s
#define CONFIG_EPK_LOAD_KEY 1
#define CONFIG_EPK_KEYRING_NAME ".epk_custom"
#define CONFIG_EPK_KEY_DESCRIPTION "epk-verification-key"

static struct key *m_epk_keyring;
static key_ref_t m_epk_main_key;
static char m_epk_hash_algo[NAME_MAX] = "sha256";
static char m_epk_file_path[PATH_MAX] = "NONE";
static char m_epk_signature_path[PATH_MAX] = "NONE";

static void epk_dump_data(const uint8_t *data, const size_t len)
{
	size_t index = 0;
	printk(KERN_INFO "");
	for (index = 0; index < len; index++)
	{
		printk(KERN_CONT "%02x", data[index]);
		//if ((index + 2) % 16 == 0)
		//	printk(KERN_CONT "\n");
	}
	printk(KERN_CONT "\n");
}

static int epk_calculate_file_hash(const char *path, const char *algo, uint8_t **output, size_t *output_len)
{
	int ret = 0;
	uint8_t *buff;
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	size_t desc_size;
	loff_t read_offset = 0;
	ssize_t read_size = 0;
	struct file *file;

	file = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(file))
	{
		pr_err("epk: Failed to open (%s) for reading\n", path);
		ret = PTR_ERR(file);
		goto err_open;
	}

	tfm = crypto_alloc_shash(algo, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
	{
		pr_err("epk: Failed to allocate hash, ret = %ld\n", PTR_ERR(tfm));
		ret = PTR_ERR(tfm);
		goto err_hash_alloc;
	}

	desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);
	desc = kzalloc(desc_size, GFP_KERNEL);
	if (!desc)
	{
		pr_err("epk: Failed to allocate %s hashing desciption\n", algo);
		ret = -ENOMEM;
		goto err_desc_alloc;
	}

	desc->tfm = tfm;
	ret = crypto_shash_init(desc);
	if (ret < 0)
	{
		pr_err("epk: Failed to init hashing algorithm\n");
		goto err_hash_init;
	}

	buff = vmalloc(PAGE_SIZE);
	if (!buff)
	{
		pr_err("epk: Failed to allocate memory for buffer to read file\n");
		ret = -ENOMEM;
		goto err_hash_init;
	}

	while ((read_size = kernel_read(file, buff, PAGE_SIZE, &read_offset)) > 0)
	{
		ret = crypto_shash_update(desc, buff, read_size);
		if (ret)
		{
			pr_err("epk: Failed to update hash\n");
			goto err_read;
		};
	}

	if (read_size < 0)
	{
		pr_err("epk: Failed to read file (%s)\n", path);
		ret = -EIO;
		goto err_read;
	}

	*output_len = crypto_shash_digestsize(tfm);
	*output = vmalloc(*output_len);
	if (!*output)
	{
		pr_err("epk: Failed to allocate memory for hash result\n");
		ret = -ENOMEM;
		goto err_read;
	}

	ret = crypto_shash_final(desc, *output);
	if (ret)
	{
		vfree(*output);
		pr_err("epk: Failed to finalize hash\n");
	}

err_read:
	vfree(buff);
err_hash_init:
	kfree(desc);
err_desc_alloc:
	crypto_free_shash(tfm);
err_hash_alloc:
	filp_close(file, NULL);
err_open:
	return ret;
}

static int epk_read_file(const char *path, uint8_t **output, size_t *output_len)
{
	int ret = 0;
	struct file *file;
	loff_t file_size = 0;
	ssize_t read_size;
	file = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(file))
	{
		pr_err("epk: Failed to open (%s) for reading\n", path);
		ret = PTR_ERR(file);
		goto err_open;
	}

	file_size = i_size_read(file->f_inode);
	*output = vmalloc(file_size);
	if (!*output)
	{
		pr_err("epk: Failed to allocate memory for buffer to read file,\n path: %s, size: %llu\n",
			   path, (unsigned long long)file_size);
		ret = -ENOMEM;
		goto err_vmalloc;
	}

	read_size = kernel_read(file, *output, file_size, 0);
	if ((read_size < 0) || (read_size != file_size))
	{
		pr_err("epk: Failed to read file (%s)\n", path);
		ret = -EIO;
		vfree(*output);
	}

	*output_len = (size_t)file_size;

err_vmalloc:
	filp_close(file, NULL);
err_open:
	return ret;
}

static int epk_verify_file(void)
{
	int ret = 0;
	struct public_key_signature pks;
	uint8_t *data = NULL;
	size_t data_len = 0;
	uint8_t *signature = NULL;
	size_t signature_len = 0;

	ret = epk_read_file(m_epk_signature_path, &signature, &signature_len);
	if (ret)
		return ret;

	// pr_info("epk: Dump Signature (%lu):\n", (unsigned long)signature_len);
	// epk_dump_data(signature, signature_len);

	ret = epk_calculate_file_hash(m_epk_file_path, m_epk_hash_algo, &data, &data_len);
	if (ret)
	{
		vfree(signature);
		return ret;
	}

	pr_info("epk: Dump file hash (%s:%lu - %s)\n", m_epk_file_path, data_len, m_epk_hash_algo);
	epk_dump_data(data, data_len);

	memset(&pks, 0, sizeof(pks));

	pks.hash_algo = m_epk_hash_algo;
	pks.pkey_algo = "rsa";
	pks.encoding = "pkcs1";
	pks.digest = data;
	pks.digest_size = data_len;
	pks.s = signature;
	pks.s_size = signature_len;
	ret = verify_signature(key_ref_to_ptr(m_epk_main_key), &pks);
	if (ret)
	{
		pr_err("epk: Failed to verify signature\n");
	}

	vfree(data);
	vfree(signature);

	return ret;
}

static ssize_t epk_key_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
#ifdef CONFIG_EPK_LOAD_KEY
	struct key *key = key_ref_to_ptr(m_epk_main_key);
#else
	struct key *key = m_epk_keyring;
#endif
	int ret = sprintf(buf, "%d : %s\n", key->serial, key->description);

	return ret;
}

static ssize_t epk_verify_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%s %s : %s\n", m_epk_file_path, m_epk_signature_path,
				   (epk_verify_file() == 0 ? "PASS" : "FAIL"));
}

static ssize_t epk_verify_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	sscanf(buf, "%" XSTR(NAME_MAX) "s %" XSTR(PATH_MAX) "s %" XSTR(PATH_MAX) "s",
		   m_epk_hash_algo, m_epk_file_path, m_epk_signature_path);
	return count;
}

static struct kobject *m_epk_kobject;
static struct kobj_attribute m_epk_key_attr = __ATTR(key, 0444, epk_key_show, NULL);
static struct kobj_attribute m_epk_verify_attr = __ATTR(verify, 0644, epk_verify_show, epk_verify_store);

static int __init epk_init(void)
{
	int ret = 0;
	const struct cred *cred = current_cred();
	key_perm_t perm = (KEY_POS_ALL & ~KEY_POS_SETATTR) | KEY_USR_VIEW | KEY_USR_READ;
	unsigned long flags = KEY_ALLOC_NOT_IN_QUOTA;

	pr_info("epk: Initialize module\n");

	m_epk_keyring = keyring_alloc(CONFIG_EPK_KEYRING_NAME, KUIDT_INIT(0), KGIDT_INIT(0),
								  cred, perm, flags, NULL, NULL);
	if (IS_ERR(m_epk_keyring))
	{
		pr_err("epk: Failed to allocate keyring (%ld)\n", PTR_ERR(m_epk_keyring));
		return PTR_ERR(m_epk_keyring);
	}

#ifdef CONFIG_EPK_LOAD_KEY
	flags |= KEY_ALLOC_BUILT_IN;
	flags |= KEY_ALLOC_BYPASS_RESTRICTION;
	m_epk_main_key = key_create_or_update(make_key_ref(m_epk_keyring, 1), "asymmetric",
										  CONFIG_EPK_KEY_DESCRIPTION,
										  EPK_X509_CERTIFICATE_DATA, EPK_X509_CERTIFICATE_LEN,
										  perm, flags);
	if (IS_ERR(m_epk_main_key))
	{
		pr_err("epk: Failed to load X.509 certificate (%ld)\n", PTR_ERR(m_epk_main_key));
		key_put(m_epk_keyring);
		return PTR_ERR(m_epk_main_key);
	}
#endif

	m_epk_kobject = kobject_create_and_add("epk", kernel_kobj);
	if (!m_epk_kobject)
	{
		key_ref_put(m_epk_main_key);
		key_put(m_epk_keyring);
		pr_err("epk: Failed to create kernel object\n");
		return -ENOMEM;
	}

	ret = sysfs_create_file(m_epk_kobject, &m_epk_key_attr.attr);
	if (ret)
	{
		key_ref_put(m_epk_main_key);
		key_put(m_epk_keyring);
		kobject_put(m_epk_kobject);
		m_epk_kobject = NULL;
		pr_err("epk: Failed to create sysfs file\n");
	}

	ret = sysfs_create_file(m_epk_kobject, &m_epk_verify_attr.attr);
	if (ret)
	{
		key_ref_put(m_epk_main_key);
		key_put(m_epk_keyring);
		sysfs_remove_file(m_epk_kobject, &m_epk_key_attr.attr);
		kobject_put(m_epk_kobject);
		m_epk_kobject = NULL;
		pr_err("epk: Failed to create sysfs file\n");
	}

	return ret;
}

static void __exit epk_exit(void)
{
	pr_info("epk: Deinitialize module\n");
	if (m_epk_kobject)
	{
		sysfs_remove_file(m_epk_kobject, &m_epk_verify_attr.attr);
		sysfs_remove_file(m_epk_kobject, &m_epk_key_attr.attr);
		kobject_put(m_epk_kobject);
	}

#ifdef CONFIG_EPK_LOAD_KEY
	if (!IS_ERR(m_epk_main_key))
		key_ref_put(m_epk_main_key);
#endif

	if (!IS_ERR(m_epk_keyring))
		key_put(m_epk_keyring);
}

module_init(epk_init);
module_exit(epk_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Elmurod A. Talipov");
MODULE_DESCRIPTION("Kernel Public Key Test Module.");
MODULE_VERSION("0.1");
