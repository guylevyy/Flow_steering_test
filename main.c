#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vl.h>
#include "infiniband/verbs.h"
#include "types.h"
#include "resources.h"
#include "test_traffic.h"

struct config_t config = {
	.ib_dev = "mlx5_0",
	.ip = "127.0.0.1",
	.num_of_iter = 8,
	.is_daemon = 1,
	.wait = 0,
	.tcp = 17500,
	.qp_type = IBV_QPT_RC,
	.msg_sz = 8,
	.ring_depth = DEF_RING_DEPTH,
	.batch_size = DEF_BATCH_SIZE,
};

struct VL_usage_descriptor_t usage_descriptor[] = {
	{
		'h', "help", "",
		"Print this message and exit",
#define HELP_CMD_CASE				0
		HELP_CMD_CASE
	},

	{
		'i', "iteration", "ITERATION",
		"Number of iterations (Default: 8)",
#define NUM_OF_ITER_CMD_CASE			1
		NUM_OF_ITER_CMD_CASE
	},

	{
		'd', "device", "DEV_ID",
		"IB device to use (Default: mlx5_0)",
#define DEV_CMD_CASE				2
		DEV_CMD_CASE
	},

	{
		'w', "wait", "",
		"Wait before exit",
#define WAIT_CMD_CASE				3
		WAIT_CMD_CASE
	},

	{
		' ', "ip", "IP_ADDR",
		"Test's Server IP",
#define IP_CMD_CASE				4
		IP_CMD_CASE
	},

	{
		' ', "tcp", "TCP",
		"TCP port to use",
#define TCP_CMD_CASE				5
		TCP_CMD_CASE
	},
};

const char *bool_to_str(int var)
{
	if (var)
		return "YES";

	return "NO";
}

static void print_config(void)
{
	VL_MISC_TRACE(("------------------- config data  -----------------"));

	VL_MISC_TRACE(("Test side                      : %s", ((config.is_daemon) ? "Server" : "Client")));
	if (!config.is_daemon)
		VL_MISC_TRACE(("Server IP                      : %s", config.ip));
	VL_MISC_TRACE(("TCP port                       : %d", config.tcp));
	VL_MISC_TRACE(("HCA                            : %s", config.ib_dev));
	VL_MISC_TRACE(("Number of iterations           : %d", config.num_of_iter));
	VL_MISC_TRACE(("Wait before exit               : %s", bool_to_str(config.wait)));

	VL_MISC_TRACE(("--------------------------------------------------"));
}

static int process_arg(
	IN		int opt_index,
	IN		char *equ_ptr,
	IN		int arr_size,
	IN		const struct VL_usage_descriptor_t *usage_desc_arr)
{
	/* process argument */

	switch (usage_descriptor[opt_index].case_code) {
	case HELP_CMD_CASE:
		VL_usage(1, arr_size, usage_desc_arr);
		exit(1);

	case NUM_OF_ITER_CMD_CASE:
		config.num_of_iter = strtoul(equ_ptr, NULL, 0);
		break;

	case DEV_CMD_CASE:
		config.ib_dev = equ_ptr;
		break;

	case WAIT_CMD_CASE:
		config.wait = 1;
		break;

	case IP_CMD_CASE:
		strcpy(config.ip, equ_ptr);
		config.is_daemon = 0;
		break;

	case TCP_CMD_CASE:
		config.tcp = strtoul(equ_ptr, NULL, 0);
		break;

	default:
		VL_MISC_ERR(("unknown parameter is the switch %s\n", equ_ptr));
		exit(4);
	}

	return 0;
}

static int parse_params(
	IN		int argc,
	IN		char **argv)
{
	int rc;

	if (argc == 1) {
		VL_MISC_ERR((" Sorry , you must enter some data."
			     " type -h for help. "));
		exit(1);
	}

	rc = VL_parse_argv(argc, argv,
			   (sizeof(usage_descriptor)/sizeof(struct VL_usage_descriptor_t)),
			   (const struct VL_usage_descriptor_t *)(usage_descriptor),
			   (const VL_process_arg_func_t)process_arg);
	return rc;
}

static int init_socket(struct resources_t *resource)
{
	struct VL_sock_props_t	sock_prop;

	if (!config.is_daemon)
		strcpy(sock_prop.ip, config.ip);

	sock_prop.is_daemon = resource->sock.is_daemon = config.is_daemon;
	sock_prop.port = resource->sock.port = config.tcp;

	/*config.sock was init in process_arg. */
	VL_sock_init(&resource->sock);

	if (VL_sock_connect(&sock_prop, &resource->sock) != 0) {
		VL_SOCK_ERR(("Fail in VL_sock_connect"));
		return FAIL;
	}

	VL_SOCK_TRACE(("Socket connection was established"));
	return SUCCESS;
}

int send_info(const struct resources_t *resource, const void *buf, size_t size)
{
	void *tmp_buf;
	int rc = SUCCESS;
	int i;

	VL_SOCK_TRACE1(("Going to send info."));

	if (size % 4) {
		VL_SOCK_ERR(("sync_info must get buffer size of multiples of 4"));
		return FAIL;
	}

	tmp_buf = calloc(1, size);
	if (!tmp_buf) {
		VL_SOCK_ERR(("Fail in alloc tmp_buf"));
		return FAIL;
	}

	for (i = 0; i < (int) (size / sizeof(uint32_t)); i++)
		((uint32_t*) tmp_buf)[i] = htonl((uint32_t) (((uint32_t*) buf)[i]));

	if (VL_sock_send(&resource->sock, size, tmp_buf)) {
		VL_SOCK_ERR(("Fail to send info"));
		rc =  FAIL;
		goto cleanup;
	}

	VL_SOCK_TRACE1(("Info was sent"));

cleanup:
	free(tmp_buf);

	return rc;
}

int recv_info(const struct resources_t *resource, void *buf, size_t size)
{
	int i;

	VL_SOCK_TRACE1(("Going to recv info."));

	if (size % 4) {
		VL_SOCK_ERR(("sync_info must get buffer size of multiples of 4"));
		return FAIL;
	}

	if (VL_sock_recv(&resource->sock, size, buf)) {
		VL_SOCK_ERR(("Fail to receive info"));
		return FAIL;
	}

	for (i = 0; i < (int) (size / sizeof(uint32_t)); i++)
		((uint32_t*) buf)[i] = ntohl((uint32_t) (((uint32_t*) buf)[i]));

	VL_SOCK_TRACE1((" Info was received"));

	return SUCCESS;
}

static int force_configurations_dependencies()
{
	if (config.ring_depth < config.batch_size)
		config.ring_depth = config.batch_size;

	return 0;
}

static int sync_configurations(struct resources_t *resource)
{
	struct sync_conf_info_t remote_info = {0};
	struct sync_conf_info_t local_info = {0};
	int rc;

	local_info.iter = config.num_of_iter;
	local_info.qp_type = config.qp_type;

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

	if (config.num_of_iter != remote_info.iter ||
	    local_info.qp_type != remote_info.qp_type) {
		VL_SOCK_ERR(("Server-client configurations are not synced"));
		return FAIL;
	}

	VL_DATA_TRACE(("Server-client configurations are synced"));

	return  SUCCESS;
}

/***********************************
* Function: main.
************************************/
int main(
	IN		int argc,
	IN		char *argv[])
{
	struct resources_t resource = {
		.sock = {
			.ip = "127.0.0.1",
			.port = 15000
		}
	};
	int rc = SUCCESS;

	rc = parse_params(argc, argv);
	CHECK_RC(rc, "parse_params");

	strcpy(resource.sock.ip, config.ip);

	rc = force_configurations_dependencies();
	CHECK_RC(rc, "force_configurations_dependencies");

	print_config();

	rc = init_socket(&resource);
	CHECK_RC(rc, "init_socket");

	rc = sync_configurations(&resource);
	CHECK_RC(rc, "sync_configurations");

	rc = alloc_resources(&resource);
	CHECK_RC(rc, "resource_alloc");

	rc = init_resources(&resource);
	CHECK_RC(rc, "resource_init");

	rc = init_qps(&resource);
	CHECK_RC(rc, "init_qps");

	rc = test_traffic(&resource);
	CHECK_RC(rc, "test_traffic");

cleanup:
	if (config.wait)
		VL_keypress_wait();

	if (resource.sock.sock_fd) {
		VL_sock_close(&resource.sock);
		VL_SOCK_TRACE(("Close the Socket"));
	}

	if (destroy_resources(&resource) != SUCCESS)
		rc = FAIL;

	VL_print_test_status(rc);

	return rc;
}

