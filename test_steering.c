#include <vl.h>
#include "types.h"
#include "main.h"
#include "test_traffic.h"
#include <ctype.h>
#include <infiniband/mlx5dv.h>

extern struct config_t config;

//convert mac string xx:xx:xx:xx:xx:xx to byte array
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

static int create_verbs_steering(struct resources_t *resource, uint8_t *mac)
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
				.dst_mac = { mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]},
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
		rc = create_verbs_steering(resource, local_eth_info.mac);
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

int destroy_steering_test(struct resources_t *resource)
{
	if (destroy_flow(resource))
		return FAIL;

	VL_MEM_TRACE(("Finish to destroy steering test resources"));

	return SUCCESS;
}

