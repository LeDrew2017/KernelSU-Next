#ifndef __KSU_H_FEATURE
#define __KSU_H_FEATURE

#include <linux/types.h>

// KernelSU feature ids.
// Kept local to this branch; the upstream legacy_susfs_v2 tree carries these in
// uapi/feature.h together with a full ioctl dispatcher. Here we only need the
// ids the selinux_hide port references.
enum ksu_feature_id {
	KSU_FEATURE_SU_COMPAT = 0,
	KSU_FEATURE_KERNEL_UMOUNT = 1,
	KSU_FEATURE_SELINUX_HIDE = 4,

	// custom extensions
	KSU_FEATURE_AVC_SPOOF = 10003,

	KSU_FEATURE_MAX = 10004
};

typedef int (*ksu_feature_get_t)(u64 *value);
typedef int (*ksu_feature_set_t)(u64 value);

struct ksu_feature_handler {
	u32 feature_id;
	const char *name;
	ksu_feature_get_t get_handler;
	ksu_feature_set_t set_handler;
};

int ksu_register_feature_handler(const struct ksu_feature_handler *handler);

int ksu_unregister_feature_handler(u32 feature_id);

int ksu_get_feature(u32 feature_id, u64 *value, bool *supported);

int ksu_set_feature(u32 feature_id, u64 value);

#endif // __KSU_H_FEATURE
