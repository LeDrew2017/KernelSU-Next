#include "feature.h"
#include "../../klog.h" // IWYU pragma: keep

#include <linux/mutex.h>
#include <linux/string.h>

// Minimal feature-handler registry for this branch.
//
// Upstream legacy_susfs_v2 indexes a flat feature_handlers[KSU_FEATURE_MAX]
// array, but here KSU_FEATURE_AVC_SPOOF (10003) would balloon that array, so we
// keep a tiny fixed-size table of registered handlers instead. This branch has
// no ioctl/prctl path wired to ksu_get_feature/ksu_set_feature yet; registration
// merely makes the feature discoverable for when that wiring lands.

#define KSU_FEATURE_HANDLER_MAX 8

static const struct ksu_feature_handler *feature_handlers[KSU_FEATURE_HANDLER_MAX];

static DEFINE_MUTEX(feature_mutex);

static int find_handler_slot(u32 feature_id)
{
	int i;

	for (i = 0; i < KSU_FEATURE_HANDLER_MAX; i++) {
		if (feature_handlers[i] && feature_handlers[i]->feature_id == feature_id)
			return i;
	}

	return -1;
}

int ksu_register_feature_handler(const struct ksu_feature_handler *handler)
{
	int slot, i;

	if (!handler) {
		pr_err("feature: register handler is NULL\n");
		return -EINVAL;
	}

	if (!handler->get_handler && !handler->set_handler) {
		pr_err("feature: no handler provided for feature %u\n",
		       handler->feature_id);
		return -EINVAL;
	}

	mutex_lock(&feature_mutex);

	slot = find_handler_slot(handler->feature_id);
	if (slot >= 0) {
		pr_warn("feature: handler for %u already registered, overwriting\n",
			handler->feature_id);
		feature_handlers[slot] = handler;
		goto out;
	}

	slot = -1;
	for (i = 0; i < KSU_FEATURE_HANDLER_MAX; i++) {
		if (!feature_handlers[i]) {
			slot = i;
			break;
		}
	}

	if (slot < 0) {
		pr_err("feature: handler table full, cannot register %u\n",
		       handler->feature_id);
		mutex_unlock(&feature_mutex);
		return -ENOSPC;
	}

	feature_handlers[slot] = handler;

	pr_info("feature: registered handler for %s (id=%u)\n",
		handler->name ? handler->name : "unknown", handler->feature_id);

out:
	mutex_unlock(&feature_mutex);
	return 0;
}

int ksu_unregister_feature_handler(u32 feature_id)
{
	int slot;
	int ret = 0;

	mutex_lock(&feature_mutex);

	slot = find_handler_slot(feature_id);
	if (slot < 0) {
		pr_warn("feature: no handler registered for %u\n", feature_id);
		ret = -ENOENT;
		goto out;
	}

	feature_handlers[slot] = NULL;

	pr_info("feature: unregistered handler for id=%u\n", feature_id);

out:
	mutex_unlock(&feature_mutex);
	return ret;
}

int ksu_get_feature(u32 feature_id, u64 *value, bool *supported)
{
	int slot;
	int ret = 0;
	const struct ksu_feature_handler *handler;

	if (!value || !supported) {
		pr_err("feature: invalid parameters\n");
		return -EINVAL;
	}

	mutex_lock(&feature_mutex);

	slot = find_handler_slot(feature_id);
	if (slot < 0) {
		*supported = false;
		*value = 0;
		pr_debug("feature: feature %u not supported\n", feature_id);
		goto out;
	}

	handler = feature_handlers[slot];
	*supported = true;

	if (!handler->get_handler) {
		pr_warn("feature: no get_handler for feature %u\n", feature_id);
		ret = -EOPNOTSUPP;
		goto out;
	}

	ret = handler->get_handler(value);
	if (ret)
		pr_err("feature: get_handler for %u failed: %d\n", feature_id, ret);

out:
	mutex_unlock(&feature_mutex);
	return ret;
}

int ksu_set_feature(u32 feature_id, u64 value)
{
	int slot;
	int ret = 0;
	const struct ksu_feature_handler *handler;

	mutex_lock(&feature_mutex);

	slot = find_handler_slot(feature_id);
	if (slot < 0) {
		pr_err("feature: feature %u not registered\n", feature_id);
		ret = -EOPNOTSUPP;
		goto out;
	}

	handler = feature_handlers[slot];

	if (!handler->set_handler) {
		pr_warn("feature: no set_handler for feature %u\n", feature_id);
		ret = -EOPNOTSUPP;
		goto out;
	}

	ret = handler->set_handler(value);
	if (ret)
		pr_err("feature: set_handler for %u failed: %d\n", feature_id, ret);

out:
	mutex_unlock(&feature_mutex);
	return ret;
}
