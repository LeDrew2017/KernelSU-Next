#ifndef __KSU_H_SELINUX_HIDE
#define __KSU_H_SELINUX_HIDE

#include <linux/types.h>

void ksu_selinux_hide_init();
void ksu_selinux_hide_exit();

// The sepolicy-tracking machinery below is only meant to be compiled into the
// translation unit that drives sepolicy handling (selinux/rules.c, which
// #includes selinux_hide.c). Other includers (e.g. ksu.c) only need the
// init/exit declarations above, so keep the rest out of their way.
#ifdef KSU_SELINUX_HIDE_INTERNAL

#include <linux/slab.h>
#include <linux/string.h>

// sepolicy command ids.
//
// This file is #included into selinux/rules.c, which uses bare CMD_* macros for
// the same commands. The upstream port keyed off KSU_SEPOLICY_CMD_* enums, so we
// alias them here to this branch's numeric values (see CMD_* in rules.c) to keep
// the ported ksu_add_shit_to_list logic intact.
enum ksu_sepolicy_cmd {
	KSU_SEPOLICY_CMD_NORMAL_PERM = 1,
	KSU_SEPOLICY_CMD_XPERM = 2,
	KSU_SEPOLICY_CMD_TYPE_STATE = 3,
	KSU_SEPOLICY_CMD_TYPE = 4,
	KSU_SEPOLICY_CMD_TYPE_ATTR = 5,
	KSU_SEPOLICY_CMD_ATTR = 6,
	KSU_SEPOLICY_CMD_TYPE_TRANSITION = 7,
	KSU_SEPOLICY_CMD_TYPE_CHANGE = 8,
	KSU_SEPOLICY_CMD_GENFSCON = 9,
};

// forward declaration — defined in selinux/rules.c which #includes this file's .c
int sepol_expected_argc(u32 cmd);

// its all push, no pop, so we can realloc forever

// types
// :type1:\0:type2:\0:type3:\0
static char *ksu_hide_type_list __read_mostly = NULL;
static size_t ksu_hide_type_len = 0;

// rules
// :src1:\0:tgt1:\0:src2:\0:tgt2:\0:src3:\0:tgt3:\0
static char *ksu_hide_rule_list __read_mostly = NULL;
static size_t ksu_hide_rule_len = 0;

static DEFINE_MUTEX(selinux_hide_list_mutex);

static void ksu_add_shit_to_list(u32 cmd, const char *args[])
{
	if (!args || !args[0])
		return;

	mutex_lock(&selinux_hide_list_mutex);

	int argc = sepol_expected_argc(cmd);

	if (cmd == KSU_SEPOLICY_CMD_TYPE || cmd == KSU_SEPOLICY_CMD_TYPE_ATTR || cmd == KSU_SEPOLICY_CMD_TYPE_STATE || cmd == KSU_SEPOLICY_CMD_ATTR) {

		const char *name = args[0];
		size_t needed_len = strlen(name) + 3; // :type:\0

		if (!ksu_hide_type_list)
			goto skip_type_dup_check;

		// anti duplicate
		size_t offset = 0;
		while (offset < ksu_hide_type_len) {
			const char *current_type = ksu_hide_type_list + offset;

			char tmp_buf[64];
			snprintf(tmp_buf, sizeof(tmp_buf), ":%s:", name);

			if (!strcmp(current_type, tmp_buf))
				goto out_unlock;

			offset = offset + strlen(current_type) + 1;
		}

	skip_type_dup_check:
		;
		size_t new_total_len = ksu_hide_type_len + needed_len;

		char *new_ptr = krealloc(ksu_hide_type_list, new_total_len, GFP_KERNEL);
		if (!new_ptr)
			goto out_unlock;

		ksu_hide_type_list = new_ptr;

		char *w_ptr = ksu_hide_type_list + ksu_hide_type_len;
		sprintf(w_ptr, ":%s:", name);

		ksu_hide_type_len = new_total_len;

		pr_info("selinux_hide: tracking type: %s\n", w_ptr );


	} else if (argc >= 2) {
		const char *src = args[0];
		const char *tgt = args[1];

		size_t src_needed = strlen(src) + 3; // :src:\0
		size_t tgt_needed = strlen(tgt) + 3; // :tgt:\0
		size_t needed_len = src_needed + tgt_needed;

		if (!ksu_hide_rule_list)
			goto skip_rule_dup_check;

		// anti duplicate
		size_t offset = 0;
		while (offset < ksu_hide_rule_len) {
			const char *src_chk = ksu_hide_rule_list + offset;
			size_t src_sz = strlen(src_chk) + 1; // for \0

			const char *tgt_chk = src_chk + src_sz;
			size_t tgt_sz = strlen(tgt_chk) + 1; // for \0

			char src_buf[64], tgt_buf[64];
			snprintf(src_buf, sizeof(src_buf), ":%s:", src);
			snprintf(tgt_buf, sizeof(tgt_buf), ":%s:", tgt);

			if (!strcmp(src_chk, src_buf) && !strcmp(tgt_chk, tgt_buf))
				goto out_unlock;

			offset = offset + src_sz + tgt_sz;
		}

	skip_rule_dup_check:
		;
		size_t new_total_len = ksu_hide_rule_len + needed_len;
		char *new_ptr = krealloc(ksu_hide_rule_list, new_total_len, GFP_KERNEL);
		if (!new_ptr)
			goto out_unlock;

		ksu_hide_rule_list = new_ptr;

		char *w_ptr_src = ksu_hide_rule_list + ksu_hide_rule_len;
		sprintf(w_ptr_src, ":%s:", src);

		char *w_ptr_tgt = w_ptr_src + strlen(w_ptr_src) + 1;
		sprintf(w_ptr_tgt, ":%s:", tgt);

		ksu_hide_rule_len = new_total_len;

		pr_info("selinux_hide: tracking rule: %s %s\n", w_ptr_src, w_ptr_tgt);

	}

out_unlock:
	mutex_unlock(&selinux_hide_list_mutex);
}

#endif // KSU_SELINUX_HIDE_INTERNAL

#endif // __KSU_H_SELINUX_HIDE
