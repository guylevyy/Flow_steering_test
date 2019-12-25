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
	int rc = SUCCESS;

	resource->table_arr = calloc(NUM_TABLES, sizeof(struct mlx5dv_dr_table *));
	if (!resource->table_arr) {
		VL_MEM_ERR(("Failed to calloc"));
		rc = FAIL;
	}

	resource->action_arr = calloc(NUM_TABLES, sizeof(struct mlx5dv_dr_action *));
	if (!resource->action_arr) {
		VL_MEM_ERR(("Failed to calloc"));
		rc = FAIL;
		goto free;
	}

	resource->matcher_arr = calloc(NUM_TABLES * NUM_MATCHERS, sizeof(struct mlx5dv_dr_matcher *));
	if (!resource->matcher_arr) {
		VL_MEM_ERR(("Failed to calloc"));
		rc = FAIL;
		goto free;
	}

	resource->rule_arr = calloc(NUM_TABLES * NUM_MATCHERS, sizeof(struct mlx5dv_dr_rule *));
	if (!resource->rule_arr) {
		VL_MEM_ERR(("Failed to calloc"));
		rc = FAIL;
		goto free;
	}

	return SUCCESS;

free:
	free(resource->table_arr);
	free(resource->action_arr);
	free(resource->matcher_arr);
	free(resource->rule_arr);

	return rc;
}

static int destroy_domain(struct resources_t *resource)
{
	int rc;

	if (!resource->domain)
		return SUCCESS;

	VL_MISC_TRACE1(("Going to mlx5dv_dr_domain_destroy"));
	rc = mlx5dv_dr_domain_destroy(resource->domain);
	if (rc) {
		VL_MISC_ERR(("Fail in mlx5dv_dr_domain_destroy (%s)", strerror(rc)));
		return FAIL;
	}

	VL_MEM_TRACE1(("Finish destroy domain"));

	return SUCCESS;
}

static int destroy_table(struct resources_t *resource)
{
	int i;
	int rc;

	if (!resource->table_arr)
		return SUCCESS;

	for (i = 0; i < NUM_TABLES; i++) {
		if (!resource->table_arr[i])
			continue;

		VL_MISC_TRACE1(("Going to destroy tabel[%d]", i));
		rc = mlx5dv_dr_table_destroy(resource->table_arr[i]);
		if (rc) {
			VL_MISC_ERR(("Fail in mlx5dv_dr_table_destroy (%s)", strerror(rc)));
			return FAIL;
		}
	}

	VL_MEM_TRACE1(("Finish destroy tables"));

	return SUCCESS;
}

static int destroy_matcher(struct resources_t *resource)
{
	int i, j;
	int rc;

	if (!resource->matcher_arr)
		return SUCCESS;

	for (i = 0; i < (NUM_TABLES * NUM_MATCHERS); i += NUM_MATCHERS) {
		for (j = 0; j < NUM_MATCHERS; j++) {
			if (!resource->matcher_arr[i + j])
				continue;

			VL_MISC_TRACE1(("Going to destroy matcher[%d]", i + j));
			rc = mlx5dv_dr_matcher_destroy(resource->matcher_arr[i + j]);
			if (rc) {
				VL_MISC_ERR(("Fail in mlx5dv_dr_matcher_destroy (%s)", strerror(rc)));
				return FAIL;
			}
		}
	}

	VL_MEM_TRACE1(("Finish destroy matchers"));

	return SUCCESS;
}

static int destroy_action(struct resources_t *resource)
{
	int i;
	int rc;

	if (!resource->action_arr)
		return SUCCESS;

	for (i = 0; i < NUM_TABLES; i++) {
		if (!resource->action_arr[i])
			continue;

		VL_MISC_TRACE1(("Going to destroy action[%d]", i));
		rc = mlx5dv_dr_action_destroy(resource->action_arr[i]);
		if (rc) {
			VL_MISC_ERR(("Fail in mlx5dv_dr_action_destroy (%s)", strerror(rc)));
			return FAIL;
		}
	}

	VL_MEM_TRACE1(("Finish destroy actions"));

	return SUCCESS;
}

static int destroy_rule(struct resources_t *resource)
{
	int i, j;
	int rc;

	if (!resource->rule_arr)
		return SUCCESS;

	for (i = 0; i < (NUM_TABLES * NUM_MATCHERS); i += NUM_MATCHERS) {
		for (j = 0; j < NUM_MATCHERS; j++) {
			if (!resource->rule_arr[i + j])
				continue;

			VL_MISC_TRACE1(("Going to destroy rule[%d]", i + j));
			rc = mlx5dv_dr_rule_destroy(resource->rule_arr[i + j]);
			if (rc) {
				VL_MISC_ERR(("Fail in mlx5dv_dr_rule_destroy (%s)", strerror(rc)));
				return FAIL;
			}
		}
	}

	VL_MEM_TRACE1(("Finish destroy rules"));

	return SUCCESS;
}

static int destroy_steering_resources(struct resources_t *resource)
{
	if (destroy_rule(resource) ||
	    destroy_action(resource) ||
	    destroy_matcher(resource) ||
	    destroy_table(resource) ||
	    destroy_domain(resource))
		return FAIL;

	free(resource->table_arr);
	free(resource->matcher_arr);
	free(resource->rule_arr);
	free(resource->action_arr);

	VL_MEM_TRACE(("Finish to destroy steering test resources"));

	return SUCCESS;
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

static int create_test_data_path_flows(struct resources_t *resource, uint8_t *dmac)
{
	struct mlx5dv_flow_match_parameters *match;
	uint16_t dmac_15_0;
	uint32_t dmac_47_16;
	int rc = SUCCESS;

	VL_MISC_TRACE1(("Going to create steering rule by mlx5dv"));

	resource->domain =
		mlx5dv_dr_domain_create(resource->hca_p->context,
				        MLX5DV_DR_DOMAIN_TYPE_NIC_RX);
	if (!resource->domain) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_domain_create (%s)", strerror(errno)));
		return FAIL;
	}

	resource->table_arr[0] = mlx5dv_dr_table_create(resource->domain, 0);
	if (!resource->table_arr[0]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_table_create level 0 (%s)", strerror(errno)));
		return FAIL;
	}

	resource->table_arr[1] = mlx5dv_dr_table_create(resource->domain, 1);
	if (!resource->table_arr[1]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_table_create level 1 (%s)", strerror(errno)));
		return FAIL;
	}

	match = calloc(1, sizeof(*match) + sizeof(struct dr_match_param));
	if (!match) {
		VL_MISC_ERR(("Fail to allocate match (%s)", strerror(errno)));
		return FAIL;
	}
	match->match_sz = sizeof(struct dr_match_param);

	resource->matcher_arr[0] =
		mlx5dv_dr_matcher_create(resource->table_arr[0], 0,
					 DR_MATCHER_CRITERIA_EMPTY, match);
	if (!resource->matcher_arr[0]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_matcher_create 0 (%s)", strerror(errno)));
		rc = FAIL;
		goto cleanup;
	}

	resource->action_arr[0] = mlx5dv_dr_action_create_dest_table(resource->table_arr[1]);
	if (!resource->action_arr[0]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_action_create_dest_table(%s)", strerror(errno)));
		rc = FAIL;
		goto cleanup;
	}

	resource->rule_arr[0] = mlx5dv_dr_rule_create(resource->matcher_arr[0], match, 1,
					       &resource->action_arr[0]);
	if (!resource->rule_arr[0]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_rule_create 0 (%s)", strerror(errno)));
		rc = FAIL;
		goto cleanup;
	}

	DEVX_SET(dr_match_spec, match->match_buf, dmac_15_0, 0xFFFFFFFF);
	DEVX_SET(dr_match_spec, match->match_buf, dmac_47_16, 0xFFFFFFFF);
	match->match_sz = sizeof(struct dr_match_param);

	resource->matcher_arr[1] =
		mlx5dv_dr_matcher_create(resource->table_arr[1], 0,
					 DR_MATCHER_CRITERIA_OUTER, match);
	if (!resource->matcher_arr[1]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_matcher_create 1 (%s)", strerror(errno)));
		rc = FAIL;
		goto cleanup;
	}

	resource->action_arr[1] = mlx5dv_dr_action_create_dest_ibv_qp(resource->qp);
	if (!resource->action_arr[1]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_action_create_dest_ibv_qp (%s)", strerror(errno)));
		rc = FAIL;
		goto cleanup;
	}

	memset(match->match_buf, 0, sizeof(struct dr_match_param)); /* Not necessarly */
	/* DEVX_SET does htobe32. The dmac[] array was stored in BE order manner.
	 * Hence, DEVX_SET parameters should be provided in host byte order.
	 */
	dmac_15_0 = dmac[4] << 8 | dmac[5];
	dmac_47_16 = dmac[0] << 24 | dmac[1] << 16 | dmac[2] << 8 | dmac[3];
	VL_MISC_TRACE1(("Set dr_match_spec DMAC %.x%.hx", dmac_47_16, dmac_15_0));
	DEVX_SET(dr_match_spec, match->match_buf, dmac_15_0, dmac_15_0);
	DEVX_SET(dr_match_spec, match->match_buf, dmac_47_16, dmac_47_16);
	match->match_sz = sizeof(struct dr_match_param);

	resource->rule_arr[1] = mlx5dv_dr_rule_create(resource->matcher_arr[1], match, 1,
					       &resource->action_arr[1]);
	if (!resource->rule_arr[1]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_rule_create 1 (%s)", strerror(errno)));
		rc = FAIL;
		goto cleanup;
	}


	int mlx5dv_dr_domain_sync(
			struct mlx5dv_dr_domain *domain,
			uint32_t flags);

	VL_MISC_TRACE1(("Finish to create steering rule"));

cleanup:
	free(match);

	return rc;

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

		rc = create_test_data_path_flows(resource, local_mac);
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
	struct mlx5dv_flow_match_parameters *match;
	uint16_t dmac_15_0;
	uint32_t dmac_47_16;
	int rc = SUCCESS;
	int i;

	VL_MISC_TRACE1(("Start control path test"));

	mac_string_to_byte(config.mac, mac);

	VL_MISC_TRACE1(("Going to mlx5dv_dr_domain_create"));
	resource->domain =
		mlx5dv_dr_domain_create(resource->hca_p->context,
				        MLX5DV_DR_DOMAIN_TYPE_NIC_RX);
	if (!resource->domain) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_domain_create (%s)", strerror(errno)));
		return FAIL;
	}

	VL_MISC_TRACE1(("Going to mlx5dv_dr_table_create level 0"));
	resource->table_arr[0] = mlx5dv_dr_table_create(resource->domain, 0);
	if (!resource->table_arr[0]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_table_create level 0 (%s)", strerror(errno)));
		return FAIL;
	}

	VL_MISC_TRACE1(("Going to mlx5dv_dr_table_create level 1"));
	resource->table_arr[1] = mlx5dv_dr_table_create(resource->domain, 1);
	if (!resource->table_arr[1]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_table_create level 1 (%s)", strerror(errno)));
		return FAIL;
	}

	match = calloc(1, sizeof(*match) + sizeof(struct dr_match_param));
	if (!match) {
		VL_MISC_ERR(("Fail to allocate match (%s)", strerror(errno)));
		return FAIL;
	}
	match->match_sz = sizeof(struct dr_match_param);

	VL_MISC_TRACE1(("Going to mlx5dv_dr_matcher_create prio 2"));
	resource->matcher_arr[0] =
		mlx5dv_dr_matcher_create(resource->table_arr[0], 2,
					 DR_MATCHER_CRITERIA_EMPTY, match);
	if (!resource->matcher_arr[0]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_matcher_create 2 (%s)", strerror(errno)));
		rc = FAIL;
		goto cleanup;
	}

	VL_MISC_TRACE1(("Going to mlx5dv_dr_matcher_create prio 0"));
	resource->matcher_arr[1] =
		mlx5dv_dr_matcher_create(resource->table_arr[0], 0,
					 DR_MATCHER_CRITERIA_EMPTY, match);
	if (!resource->matcher_arr[1]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_matcher_create 0 (%s)", strerror(errno)));
		rc = FAIL;
		goto cleanup;
	}

	VL_MISC_TRACE1(("Going to mlx5dv_dr_matcher_create prio 1"));
	resource->matcher_arr[2] =
		mlx5dv_dr_matcher_create(resource->table_arr[0], 1,
					 DR_MATCHER_CRITERIA_EMPTY, match);
	if (!resource->matcher_arr[2]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_matcher_create 1 (%s)", strerror(errno)));
		rc = FAIL;
		goto cleanup;
	}

	VL_MISC_TRACE1(("Going to mlx5dv_dr_action_create_dest_table"));
	resource->action_arr[0] = mlx5dv_dr_action_create_dest_table(resource->table_arr[1]);
	if (!resource->action_arr[0]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_action_create_dest_table(%s)", strerror(errno)));
		rc = FAIL;
		goto cleanup;
	}

	/* Insert rules to table 0 matchers*/
	for (i = 0; i < NUM_MATCHERS; i++) {
		VL_MISC_TRACE1(("Going to create rule [%d]", i));
		resource->rule_arr[i] =
			mlx5dv_dr_rule_create(resource->matcher_arr[i], match, 1,
					      &resource->action_arr[0]);
		if (!resource->rule_arr[i]) {
			VL_MISC_ERR(("Fail with mlx5dv_dr_rule_create (%s)", strerror(errno)));
			rc = FAIL;
			goto cleanup;
		}
	}

	DEVX_SET(dr_match_spec, match->match_buf, dmac_15_0, 0xFFFFFFFF);
	DEVX_SET(dr_match_spec, match->match_buf, dmac_47_16, 0xFFFFFFFF);
	match->match_sz = sizeof(struct dr_match_param);

	/* Create matcher for table 1 */
	VL_MISC_TRACE1(("Going to mlx5dv_dr_matcher_create prio 0 for table 1"));
	resource->matcher_arr[NUM_MATCHERS] =
		mlx5dv_dr_matcher_create(resource->table_arr[1], 0,
					 DR_MATCHER_CRITERIA_OUTER, match);
	if (!resource->matcher_arr[NUM_MATCHERS]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_matcher_create (%s)", strerror(errno)));
		rc = FAIL;
		goto cleanup;
	}

	VL_MISC_TRACE1(("Going to mlx5dv_dr_action_create_dest_ibv_qp"));
	resource->action_arr[1] = mlx5dv_dr_action_create_dest_ibv_qp(resource->qp);
	if (!resource->action_arr[1]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_action_create_dest_ibv_qp (%s)", strerror(errno)));
		rc = FAIL;
		goto cleanup;
	}

	memset(match->match_buf, 0, sizeof(struct dr_match_param)); /* Not necessarly */
	/* DEVX_SET does htobe32. The dmac[] array was stored in BE order manner.
	 * Hence, DEVX_SET parameters should be provided in host byte order.
	 */
	dmac_15_0 = mac[4] << 8 | mac[5];
	dmac_47_16 = mac[0] << 24 | mac[1] << 16 | mac[2] << 8 | mac[3];
	VL_MISC_TRACE1(("Set dr_match_spec DMAC %.x%.hx", dmac_47_16, dmac_15_0));
	DEVX_SET(dr_match_spec, match->match_buf, dmac_15_0, dmac_15_0);
	DEVX_SET(dr_match_spec, match->match_buf, dmac_47_16, dmac_47_16);
	match->match_sz = sizeof(struct dr_match_param);

	/* Insert rule to table 1 */
	VL_MISC_TRACE1(("Going to create rule [NUM_MATCHERS]"));
	resource->rule_arr[NUM_MATCHERS] = mlx5dv_dr_rule_create(resource->matcher_arr[NUM_MATCHERS], match, 1,
					       &resource->action_arr[1]);
	if (!resource->rule_arr[NUM_MATCHERS]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_rule_create (%s)", strerror(errno)));
		rc = FAIL;
		goto cleanup;
	}

	VL_MISC_TRACE1(("Finish to create"));

cleanup:
	free(match);

	return rc;

}

int test_steering_control_path(struct resources_t *resource)
{
	int rc;

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

