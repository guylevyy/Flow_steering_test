#include <vl.h>
#include "types.h"
#include "main.h"
#include "test_traffic.h"
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

static int create_mlx5dv_steering(struct resources_t *resource, uint8_t *dmac)
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

	resource->table[0] = mlx5dv_dr_table_create(resource->domain, 0);
	if (!resource->table[0]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_table_create level 0 (%s)", strerror(errno)));
		return FAIL;
	}

	resource->table[1] = mlx5dv_dr_table_create(resource->domain, 1);
	if (!resource->table[1]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_table_create level 1 (%s)", strerror(errno)));
		return FAIL;
	}

	match = calloc(1, sizeof(*match) + sizeof(struct dr_match_param));
	if (!match) {
		VL_MISC_ERR(("Fail to allocate match (%s)", strerror(errno)));
		return FAIL;
	}
	match->match_sz = sizeof(struct dr_match_param);

	resource->matcher[0] =
		mlx5dv_dr_matcher_create(resource->table[0], 0,
					 DR_MATCHER_CRITERIA_EMPTY, match);
	if (!resource->matcher[0]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_matcher_create 0 (%s)", strerror(errno)));
		rc = FAIL;
		goto cleanup;
	}

	resource->action[0] = mlx5dv_dr_action_create_dest_table(resource->table[1]);
	if (!resource->action[0]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_action_create_dest_table(%s)", strerror(errno)));
		rc = FAIL;
		goto cleanup;
	}

	resource->rule[0] = mlx5dv_dr_rule_create(resource->matcher[0], match, 1,
					       &resource->action[0]);
	if (!resource->rule[0]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_rule_create 0 (%s)", strerror(errno)));
		rc = FAIL;
		goto cleanup;
	}

	DEVX_SET(dr_match_spec, match->match_buf, dmac_15_0, 0xFFFFFFFF);
	DEVX_SET(dr_match_spec, match->match_buf, dmac_47_16, 0xFFFFFFFF);
	match->match_sz = sizeof(struct dr_match_param);

	resource->matcher[1] =
		mlx5dv_dr_matcher_create(resource->table[1], 0,
					 DR_MATCHER_CRITERIA_OUTER, match);
	if (!resource->matcher[1]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_matcher_create 1 (%s)", strerror(errno)));
		rc = FAIL;
		goto cleanup;
	}

	resource->action[1] = mlx5dv_dr_action_create_dest_ibv_qp(resource->qp);
	if (!resource->action[1]) {
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

	resource->rule[1] = mlx5dv_dr_rule_create(resource->matcher[1], match, 1,
					       &resource->action[1]);
	if (!resource->rule[1]) {
		VL_MISC_ERR(("Fail with mlx5dv_dr_rule_create 1 (%s)", strerror(errno)));
		rc = FAIL;
		goto cleanup;
	}

/*
	int mlx5dv_dr_domain_sync(
			struct mlx5dv_dr_domain *domain,
			uint32_t flags);
*/
	VL_MISC_TRACE1(("Finish to create steering rule"));

cleanup:
	free(match);

	return rc;

}

static int create_verbs_steering(struct resources_t *resource, uint8_t *dmac)
{
	struct raw_eth_flow_attr flow_attr = {
		.attr = {
			.comp_mask      = 0,
			.type           = IBV_FLOW_ATTR_NORMAL,
			.size           = sizeof(flow_attr),
			.priority       = 0,
			.num_of_specs   = 1,
			.port           = IB_PORT,
			.flags          = 0,
		},
		.spec_eth = {
			.type   = IBV_FLOW_SPEC_ETH,
			.size   = sizeof(struct ibv_flow_spec_eth),
			.val = {
				.dst_mac = { dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5]},
				.src_mac = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				.ether_type = 0,
				.vlan_tag = 0,
			},
			.mask = {
				.dst_mac = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
				.src_mac = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				.ether_type = 0,
				.vlan_tag = 0,
			}
		}
	};

	VL_MISC_TRACE1(("Going to create steering rule by verbs"));

	resource->flow = ibv_create_flow(resource->qp , &flow_attr.attr);
	if (!resource->flow) {
		VL_MISC_ERR(("Fail with ibv_create_flow (%s)", strerror(errno)));
		return FAIL;
	}

	VL_MISC_TRACE1(("Finish to create steering rule"));

	return SUCCESS;
}

int test_steering(struct resources_t *resource)
{
	struct sync_eth_info_t remote_eth_info = {{0}};
	struct sync_eth_info_t local_eth_info = {{0}};
	int rc;

	mac_string_to_byte(config.mac, local_eth_info.mac);

	if (!config.is_daemon) {
		rc = send_info(resource, &local_eth_info, sizeof(local_eth_info));
		if (rc)
			return FAIL;

		rc = recv_info(resource, &remote_eth_info, sizeof(remote_eth_info));
		if (rc)
			return FAIL;
	} else {
		rc = recv_info(resource, &remote_eth_info, sizeof(remote_eth_info));
		if (rc)
			return FAIL;

		rc = send_info(resource, &local_eth_info, sizeof(local_eth_info));
		if (rc)
			return FAIL;
	}

	VL_MISC_TRACE(("Finish to sync packets headers"));

	if (config.is_daemon) {
		VL_MISC_TRACE(("Creating flows"));
		rc = create_mlx5dv_steering(resource, local_eth_info.mac);
	} else {
		VL_MISC_TRACE(("Creating headers"));
		rc = create_headers(resource, local_eth_info.mac, remote_eth_info.mac);
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

static int destroy_flow(struct resources_t *resource)
{
	int rc;

	if (!resource->flow)
		return SUCCESS;

	VL_MISC_TRACE1(("Going to ibv_destroy_flow"));
	rc = ibv_destroy_flow(resource->flow);
	if (rc) {
		VL_MISC_ERR(("Fail in ibv_destroy_flow (%s)", strerror(rc)));
		return FAIL;
	}

	VL_MEM_TRACE1(("Finish destroy flow"));

	return SUCCESS;
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
	int rc = SUCCESS;

	for (i = 0; i < NUM_TABLES; i++) {
		if (!resource->table[i])
			continue;

		VL_MISC_TRACE1(("Going to destroy tabel[%d]", i));
		rc = mlx5dv_dr_table_destroy(resource->table[i]);
		if (rc) {
			VL_MISC_ERR(("Fail in mlx5dv_dr_table_destroy (%s)", strerror(rc)));
		}
	}

	VL_MEM_TRACE1(("Finish destroy tables"));

	return rc;
}

static int destroy_matcher(struct resources_t *resource)
{
	int i;
	int rc = SUCCESS;

	for (i = 0; i < NUM_TABLES; i++) {
		if (!resource->matcher[i])
			continue;

		VL_MISC_TRACE1(("Going to destroy matcher[%d]", i));
		rc = mlx5dv_dr_matcher_destroy(resource->matcher[i]);
		if (rc) {
			VL_MISC_ERR(("Fail in mlx5dv_dr_matcher_destroy (%s)", strerror(rc)));
		}
	}

	VL_MEM_TRACE1(("Finish destroy matchers"));

	return rc;
}

static int destroy_action(struct resources_t *resource)
{
	int i;
	int rc = SUCCESS;

	for (i = 0; i < NUM_TABLES; i++) {
		if (!resource->action[i])
			continue;

		VL_MISC_TRACE1(("Going to destroy action[%d]", i));
		rc = mlx5dv_dr_action_destroy(resource->action[i]);
		if (rc) {
			VL_MISC_ERR(("Fail in mlx5dv_dr_action_destroy (%s)", strerror(rc)));
		}
	}

	VL_MEM_TRACE1(("Finish destroy actions"));

	return rc;
}

static int destroy_rule(struct resources_t *resource)
{
	int i;
	int rc = SUCCESS;

	for (i = 0; i < NUM_TABLES; i++) {
		if (!resource->rule[i])
			continue;

		VL_MISC_TRACE1(("Going to destroy rule[%d]", i));
		rc = mlx5dv_dr_rule_destroy(resource->rule[i]);
		if (rc) {
			VL_MISC_ERR(("Fail in mlx5dv_dr_rule_destroy (%s)", strerror(rc)));
		}
	}

	VL_MEM_TRACE1(("Finish destroy rules"));

	return rc;
}

int destroy_steering_test(struct resources_t *resource)
{
	if (destroy_flow(resource) ||
	    destroy_rule(resource) ||
	    destroy_action(resource) ||
	    destroy_matcher(resource) ||
	    destroy_table(resource) ||
	    destroy_domain(resource))
		return FAIL;

	VL_MEM_TRACE(("Finish to destroy steering test resources"));

	return SUCCESS;
}

