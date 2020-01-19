#include <vl.h>
#include "types.h"
#include "main.h"
#include "test_traffic.h"
#include "resources.h"
#include "mlx5dv_dr.h"
#include <ctype.h>
#include <infiniband/mlx5dv.h>

extern struct config_t config;

//convert mac string xx:xx:xx:xx:xx:xx to byte array by BE order (i.e. MSB is in array[0]).
#define MAC_SEP ':'
static char *mac_string_to_byte(const char *mac_string, uint8_t *mac_bytes)
{
	int counter;
	for (counter = 0; counter < 6; ++counter) {
		unsigned int number = 0;
		char ch;

		//Convert letter into lower case.
		ch = tolower(*mac_string++);

		if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f')) {
			return NULL;
		}

		number = isdigit (ch) ? (ch - '0') : (ch - 'a' + 10);
		ch = tolower(*mac_string);

		if ((counter < 5 && ch != MAC_SEP) || (counter == 5 && ch != '\0'
				&& !isspace (ch))) {
			++mac_string;

			if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f')) {
				return NULL;
			}

			number <<= 4;
			number += isdigit (ch) ? (ch - '0') : (ch - 'a' + 10);
			ch = *mac_string;

			if (counter < 5 && ch != MAC_SEP) {
				return NULL;
			}
		}
		mac_bytes[counter] = (unsigned char) number;
		++mac_string;
	}
	return (char *) mac_bytes;
}

static void init_eth_header(struct resources_t *resource, uint8_t *smac, uint8_t *dmac)
{
	struct ETH_header *eth_header = resource->mr->addr;
	size_t frame_size = config.msg_sz;

	memcpy(eth_header->src_mac, smac, MAC_LEN);
	memcpy(eth_header->dst_mac, dmac, MAC_LEN);
	eth_header->eth_type = htons(frame_size - ETH_HDR_SIZE); /* Payload and CRC */

	VL_MISC_TRACE1(("Create header's DMAC %x:%x:%x:%x:%x:%x",
			dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5]));
}

static int create_headers(struct resources_t *resource, uint8_t *smac, uint8_t *dmac)
{
	init_eth_header(resource, smac, dmac);

	VL_MISC_TRACE1(("Finish to create headers"));

	return SUCCESS;
}

static int init_steering_resources(struct resources_t *resource)
{
	resource->tree = calloc(1, sizeof(*resource->tree));
	if (!resource->tree) {
		VL_MEM_ERR(("Failed to calloc tree"));
		return FAIL;
	}

	return SUCCESS;
}

static int destroy_tree(struct resources_t *resource)
{
	uint32_t i, j, k;
	int rc;

	if (!resource->tree)
		return SUCCESS;

	for (i = 0; i < MAX_NUM_TABLES; i++) {
		if (!resource->tree->tables[i].tbl)
			continue;

		VL_MISC_TRACE1(("Going to destroy tables[%d].matchers", i));
		for (j = 0; j < MAX_NUM_MATCHERS; j++) {
			if (!resource->tree->tables[i].matchers[j].matcher)
				continue;

			VL_MISC_TRACE1(("Going to destroy tables[%d].matchers[%d].rules", i, j));
			for (k = 0; k < config.num_of_iter; k++) {
				if (!resource->tree->tables[i].matchers[j].rules[k].rule)
					continue;

				VL_MISC_TRACE1(("Going to destroy tables[%d].matchers[%d].rules[%d]", i, j, k));

				rc = mlx5dv_dr_rule_destroy(resource->tree->tables[i].matchers[j].rules[k].rule);
				if (rc) {
					VL_MISC_ERR(("Fail in mlx5dv_dr_rule_destroy (%s)", strerror(rc)));
					return FAIL;
				}
			}

			VL_MISC_TRACE1(("Going to destroy tables[%d].matchers[%d]", i, j));
			rc = mlx5dv_dr_matcher_destroy(resource->tree->tables[i].matchers[j].matcher);
			if (rc) {
				VL_MISC_ERR(("Fail in mlx5dv_dr_matcher_destroy (%s)", strerror(rc)));
				return FAIL;
			}
		}

		if (resource->tree->tables[i].action) {
			VL_MISC_TRACE1(("Going to destroy tables[%d].action", i));
			rc = mlx5dv_dr_action_destroy(resource->tree->tables[i].action);
			if (rc) {
				VL_MISC_ERR(("Fail in mlx5dv_dr_action_destroy (%s)", strerror(rc)));
				return FAIL;
			}
		}

		VL_MISC_TRACE1(("Going to destroy tables[%d] ", i));
		rc = mlx5dv_dr_table_destroy(resource->tree->tables[i].tbl);
		if (rc) {
			VL_MISC_ERR(("Fail in mlx5dv_dr_table_destroy (%s)", strerror(rc)));
			return FAIL;
		}
	}

	if(!resource->tree->domain)
		return SUCCESS;

	VL_MISC_TRACE1(("Going to destroy domain"));
	rc = mlx5dv_dr_domain_destroy(resource->tree->domain);
	if (rc) {
		VL_MISC_ERR(("Fail in mlx5dv_dr_domain_destroy (%s)", strerror(rc)));
		return FAIL;
	}

	VL_MEM_TRACE1(("Finish destroy tree"));

	return SUCCESS;
}

static int destroy_steering_resources(struct resources_t *resource)
{
	if (destroy_tree(resource))
		return FAIL;

	free(resource->tree);

	VL_MEM_TRACE(("Finish to destroy steering test resources"));

	return SUCCESS;
}

static int build_matchers(struct table_t *tbl,
			  enum dr_matcher_criteria criteria,
			  void *match) {
	int i;

	for (i = 0; i < MAX_NUM_MATCHERS; i++) {
		VL_MISC_TRACE1(("Going to create matcher priority %d", i));

		tbl->matchers[i].matcher =
			mlx5dv_dr_matcher_create(tbl->tbl, i, criteria, match);
		if (!tbl->matchers[i].matcher) {
			VL_MISC_ERR(("Fail with mlx5dv_dr_matcher_create priority %d (%s)", i, strerror(errno)));
			return FAIL;
		}
	}

	return  SUCCESS;
}

static int populate_matchers_empty_criteria(struct table_t *tbl, void *match,
					    struct mlx5dv_dr_action *action)
{
	int i;

	for (i = 0; i < MAX_NUM_MATCHERS; i++) {
		struct rule_t *rule = &tbl->matchers[i].rules[0];

		VL_MISC_TRACE1(("Going to create matcher[%d].rule[%d]", i, 0));
		rule->rule = mlx5dv_dr_rule_create(tbl->matchers[i].matcher, match, 1, &action);
		if (!rule->rule) {
			VL_MISC_ERR(("Fail with mlx5dv_dr_rule_create (%s)", strerror(errno)));
			return FAIL;
		}
	}

	return  SUCCESS;
}

static int populate_matchers(struct table_t *tbl, void *match, struct mlx5dv_dr_action *action)
{
	uint32_t i;

	for (i = 0; i < MAX_NUM_MATCHERS; i++) {
		uint32_t j;

		for (j = 0; j < config.num_of_iter; j++) {
			struct rule_t *rule = &tbl->matchers[i].rules[j];

			VL_MISC_TRACE1(("Going to create matcher[%d].rule[%d]", i, j));
			rule->rule = mlx5dv_dr_rule_create(tbl->matchers[i].matcher, match, 1, &action);
			if (!rule->rule) {
				VL_MISC_ERR(("Fail with mlx5dv_dr_rule_create (%s)", strerror(errno)));
				return FAIL;
			}
		}
	}

	return  SUCCESS;
}

static int create_basic_tree(struct resources_t *resource, uint8_t tree_rank, uint8_t *mac)
{
	struct mlx5dv_flow_match_parameters *mask_0 = NULL;
	struct mlx5dv_flow_match_parameters *mask_1 = NULL;
	struct mlx5dv_flow_match_parameters *match_1 = NULL;
	uint16_t dmac_15_0;
	uint32_t dmac_47_16;
	int rc = SUCCESS;
	int i;

	VL_MISC_TRACE1(("Going to mlx5dv_dr_domain_create"));
	resource->tree->domain =
		mlx5dv_dr_domain_create(resource->hca_p->context,
				        MLX5DV_DR_DOMAIN_TYPE_NIC_RX);
	if (!resource->tree->domain) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_domain_create (%s)", strerror(errno)));
		return FAIL;
	}

	VL_MISC_TRACE1(("Set mask_0"));
	mask_0 = calloc(1, sizeof(*mask_0) + sizeof(struct dr_match_param));
	if (!mask_0) {
		VL_MISC_ERR(("Fail to allocate mask_0 buffer (%s)", strerror(errno)));
		return FAIL;
	}
	mask_0->match_sz = sizeof(struct dr_match_param);

	VL_MISC_TRACE1(("Set mask_1"));
	mask_1 = calloc(1, sizeof(*mask_1) + sizeof(struct dr_match_param));
	if (!mask_1) {
		VL_MISC_ERR(("Fail to allocate mask_1 buffer (%s)", strerror(errno)));
		goto cleanup;
	}
	mask_1->match_sz = sizeof(struct dr_match_param);
	/* DEVX_SET does htobe32. The dmac[] array was stored in BE order manner.
	 * Hence, DEVX_SET parameters should be provided in host byte order.
	 */
	DEVX_SET(dr_match_spec, mask_1->match_buf, dmac_15_0, 0xFFFFFFFF);
	DEVX_SET(dr_match_spec, mask_1->match_buf, dmac_47_16, 0xFFFFFFFF);

	VL_MISC_TRACE1(("Set match_1"));
	match_1 = calloc(1, sizeof(*match_1) + sizeof(struct dr_match_param));
	if (!match_1) {
		VL_MISC_ERR(("Fail to allocate match_1 buffer (%s)", strerror(errno)));
		return FAIL;
	}
	match_1->match_sz = sizeof(struct dr_match_param);

	dmac_15_0 = mac[4] << 8 | mac[5];
	dmac_47_16 = mac[0] << 24 | mac[1] << 16 | mac[2] << 8 | mac[3];
	VL_MISC_TRACE1(("Set match_1 DMAC %.x%.hx", dmac_47_16, dmac_15_0));
	DEVX_SET(dr_match_spec, match_1->match_buf, dmac_15_0, dmac_15_0);
	DEVX_SET(dr_match_spec, match_1->match_buf, dmac_47_16, dmac_47_16);

	for (i = tree_rank - 1; i >= 0; i--) {
		struct mlx5dv_dr_action *action;
		enum dr_matcher_criteria criteria;
		struct mlx5dv_flow_match_parameters *match;
		struct mlx5dv_flow_match_parameters *mask;

		VL_MISC_TRACE1(("Going to create table level %d", i));

		resource->tree->tables[i].tbl = mlx5dv_dr_table_create(resource->tree->domain, i);
		if (!resource->tree->tables[i].tbl) {
			VL_MISC_ERR(("Fail with mlx5dv_dr_table_create level %d (%s)", i, strerror(errno)));
			rc = FAIL;
			goto cleanup;
		}

		if (i == 0) {
			criteria = DR_MATCHER_CRITERIA_EMPTY;
			mask = mask_0;
			match = mask;
		} else {
			criteria = DR_MATCHER_CRITERIA_OUTER;
			mask = mask_1;
			match = match_1;
		}

		rc = build_matchers(&resource->tree->tables[i], criteria, mask);
		if (rc)
			goto cleanup;

		VL_MISC_TRACE1(("Going to create an action for table level %d", i));

		if (i == (tree_rank - 1)) {
			action = mlx5dv_dr_action_create_dest_ibv_qp(resource->qp);
			if (!action) {
				VL_MISC_ERR(("Fail with mlx5dv_dr_action_create_dest_table (%s)", strerror(errno)));
				rc = FAIL;
				goto cleanup;
			}
		} else {
			action = mlx5dv_dr_action_create_dest_table(resource->tree->tables[i + 1].tbl);
			if (!action) {
				VL_MISC_ERR(("Fail with mlx5dv_dr_action_create_dest_table (%s)", strerror(errno)));
				rc = FAIL;
				goto cleanup;
			}
		}

		resource->tree->tables[i].action = action;

		VL_MISC_TRACE1(("Going to insert rules into matchers table level %d:", i));
		if (criteria == DR_MATCHER_CRITERIA_EMPTY)
			rc = populate_matchers_empty_criteria(&resource->tree->tables[i], match, action);
		else
			rc = populate_matchers(&resource->tree->tables[i], match, action);
		if (rc)
			goto cleanup;
	}

	VL_MISC_TRACE1(("Finish to create"));

cleanup:
	free(mask_0);
	free(mask_1);
	free(match_1);

	return rc;
}

static int force_data_path_test_configurations()
{
	if (config.ring_depth < config.batch_size)
		config.ring_depth = config.batch_size;

	if (config.qp_type == IBV_QPT_RAW_PACKET &&
	    config.msg_sz < 64) {
		VL_MISC_ERR(("Ethernet packet requires minimum 64B of packet size\n"));
		return FAIL;
	}

	if (config.qp_type == IBV_QPT_RAW_PACKET &&
	    strlen(config.mac) != STR_MAC_LEN - 1) {
		VL_MISC_ERR(("Invalid local MAC address %d\n", strlen(config.mac)));
		return FAIL;
	}

	return 0;
}

static int sync_data_path_test_configurations(struct resources_t *resource)
{
	struct sync_data_path_test_t remote_info = {0};
	struct sync_data_path_test_t local_info = {0};
	int rc;

	local_info.iter = config.num_of_iter;
	mac_string_to_byte(config.mac, local_info.mac);

	if (!config.is_daemon) {
		rc = send_info(resource, &local_info, sizeof(local_info));
		if (rc)
			return FAIL;

		rc = recv_info(resource, &remote_info, sizeof(remote_info));
		if (rc)
			return FAIL;
	} else {
		rc = recv_info(resource, &remote_info, sizeof(remote_info));
		if (rc)
			return FAIL;

		rc = send_info(resource, &local_info, sizeof(local_info));
		if (rc)
			return FAIL;
	}

	if (config.num_of_iter != remote_info.iter) {
		VL_SOCK_ERR(("Server-client configurations are not synced"));
		return FAIL;
	}

	memcpy(resource->remote_mac, remote_info.mac, sizeof(resource->remote_mac));

	VL_DATA_TRACE(("Server-client configurations are synced"));

	return  SUCCESS;
}

static int _test_steering_data_path(struct resources_t *resource)
{
	uint8_t local_mac[8] = {0};
	int rc;

	if (!mac_string_to_byte(config.mac, local_mac)) {
		VL_MISC_ERR(("Fail to parse local mac"));
		return FAIL;
	}

	VL_MISC_TRACE1(("Start data-path test case"));

	if (config.is_daemon) {
		VL_MISC_TRACE(("Creating flows"));

		rc = init_steering_resources(resource);
		if (rc) {
			VL_MISC_ERR(("Fail to init_steering_resources"));
			return FAIL;
		}

		rc = create_basic_tree(resource, 2, local_mac);
	} else {
		VL_MISC_TRACE(("Creating headers"));
		rc = create_headers(resource, local_mac, resource->remote_mac);
	}
	if (rc)
		return FAIL;

	if (VL_sock_sync_ready(&resource->sock)) {
		VL_SOCK_ERR(("Sync before traffic"));
		return FAIL;
	}

	VL_MISC_TRACE(("Test traffic"));

	test_traffic(resource, config.num_of_iter);

	return SUCCESS;
}

int test_steering_data_path(struct resources_t *resource)
{
	int rc;

	rc = init_socket(resource);
	CHECK_RC(rc, "init_socket");

	rc = force_data_path_test_configurations();
	CHECK_RC(rc, "force_data_path_test_configurations");

	rc = sync_data_path_test_configurations(resource);
	CHECK_RC(rc, "sync_data_path_test_configurations");

	rc = alloc_resources(resource);
	CHECK_RC(rc, "resource_alloc");

	rc = init_resources(resource);
	CHECK_RC(rc, "resource_init");

	rc = init_qps(resource);
	CHECK_RC(rc, "init_qps");

	rc = _test_steering_data_path(resource);
	CHECK_RC(rc, "test_traffic");

cleanup:
	if (config.wait)
		VL_keypress_wait();

	if (resource->sock.sock_fd) {
		VL_sock_close(&resource->sock);
		VL_SOCK_TRACE(("Close the Socket"));
	}

	if (destroy_steering_resources(resource) != SUCCESS)
		rc = FAIL;

	if (destroy_resources(resource) != SUCCESS)
		rc = FAIL;

	return rc;
}

static int _test_steering_control_path(struct resources_t *resource)
{
	uint8_t mac[8] = {0};
	int rc = SUCCESS;

	VL_MISC_TRACE1(("Start control path test"));

	mac_string_to_byte(config.mac, mac);

	rc = create_basic_tree(resource, MAX_NUM_TABLES, mac);
	if (rc)
		return FAIL;

	return SUCCESS;
}

static int force_control_path_test_configurations()
{
	if (config.num_of_iter > MAX_NUM_RULES)
		return FAIL;

	return 0;
}

int test_steering_control_path(struct resources_t *resource)
{
	int rc;

	rc = force_control_path_test_configurations();
	CHECK_RC(rc, "force_control_path_test_configurations");

	rc = alloc_resources(resource);
	CHECK_RC(rc, "resource_alloc");

	rc = init_resources(resource);
	CHECK_RC(rc, "init_hca");

	rc = init_steering_resources(resource);
	CHECK_RC(rc, "init_steering_resources");

	rc = _test_steering_control_path(resource);
	CHECK_RC(rc, "_test_steering_control_path");

cleanup:
	if (config.wait)
		VL_keypress_wait();

	if (destroy_steering_resources(resource) != SUCCESS)
		rc = FAIL;

	if (destroy_resources(resource) != SUCCESS)
		rc = FAIL;

	return rc;
}

