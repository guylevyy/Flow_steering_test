#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vl.h>
#include "infiniband/verbs.h"
#include "types.h"
#include "resources.h"
#include "test_steering.h"

struct config_t config = {
	.ib_dev = "mlx5_0",
	.ip = "127.0.0.1",
	.num_of_iter = 8,
	.is_daemon = 1,
	.wait = 0,
	.tcp = 17500,
	.qp_type = IBV_QPT_RAW_PACKET,
	.msg_sz = 64,
	.ring_depth = DEF_RING_DEPTH,
	.batch_size = DEF_BATCH_SIZE,
	.test_case = TEST_CASE_CONTROL_A,
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

	{
		' ', "mac", "MAC_ADDR",
		"For data-path cases: local mac to use for Raw packet QP transport\n"
		"\t\t\t     For control-path cases: match criteria dmac mask and the base dmac to spread mac addresses",
#define MAC_CMD_CASE				6
		MAC_CMD_CASE
	},

	{
		't', "test", "TEST",
		"Test case [0-1] (Default: 1):"
		"\n\t\t\t\t0: data-path"
		"\n\t\t\t\t1: control path A",
#define TEST_CMD_CASE				7
		TEST_CMD_CASE
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
	VL_MISC_TRACE(("MAC                            : %s", config.mac));
	VL_MISC_TRACE(("Wait before exit               : %s", bool_to_str(config.wait)));
	VL_MISC_TRACE(("Test case                      : %d", config.test_case));

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

	case MAC_CMD_CASE:
		strcpy(config.mac, equ_ptr);
		break;

	case TEST_CMD_CASE:
		config.test_case = strtoul(equ_ptr, NULL, 0);
		if (config.test_case > 1)
			VL_MISC_ERR(("Unsupported test case %s\n", equ_ptr));
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

int init_socket(struct resources_t *resource)
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

	print_config();

	if (config.test_case == TEST_CASE_DATA_PATH)
		rc = test_steering_data_path(&resource);
	else if (config.test_case == TEST_CASE_CONTROL_A)
		rc = test_steering_control_path(&resource);

cleanup:
	VL_print_test_status(rc);

	return rc;
}

