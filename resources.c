#include <unistd.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sched.h>
#include <vl.h>
#include <vl_verbs.h>
#include "resources.h"
#include "main.h"

extern struct config_t config;

int alloc_resources(struct resources_t *resource)
{
	size_t size;

	size = sizeof(struct mr_data_t);
	resource->mr = VL_MALLOC(size, struct mr_data_t);
	if (!resource->mr) {
		VL_MEM_ERR(("Failed to malloc mr"));
		return FAIL;
	}
	memset(resource->mr, 0, size);

	resource->mr->addr = VL_MALLOC(config.msg_sz, void);
	if (!resource->mr->addr) {
		VL_MEM_ERR(("Failed to malloc data buffer"));
		return FAIL;
	}
	VL_MEM_TRACE1(("Data buffer address %p", resource->mr->addr));

	size = config.batch_size * sizeof(struct ibv_wc);
	resource->wc_arr = VL_MALLOC(size, struct ibv_wc);
	if (!resource->wc_arr) {
		VL_MEM_ERR(("Fail in alloc wr_arr"));
		return FAIL;
	}
	memset(resource->wc_arr, 0, size);

	size = config.batch_size * sizeof(struct ibv_sge) * DEF_NUM_SGE;
	resource->sge_arr = VL_MALLOC(size, struct ibv_sge);
	if (!resource->sge_arr) {
		VL_MEM_ERR(("Failed to malloc sge_arr"));
		return FAIL;
	}
	memset(resource->sge_arr, 0, size);

	size = config.batch_size * sizeof(struct ibv_send_wr);
	resource->send_wr_arr = VL_MALLOC(size, struct ibv_send_wr);
	if (!resource->send_wr_arr) {
		VL_MEM_ERR(("Fail in alloc send_wr_arr"));
		return FAIL;
	}
	memset(resource->send_wr_arr, 0, size);

	size = config.batch_size * sizeof(struct ibv_recv_wr);
	resource->recv_wr_arr = VL_MALLOC(size, struct ibv_recv_wr);
	if (!resource->recv_wr_arr) {
		VL_MEM_ERR(("Fail in alloc recv_wr_arr"));
		return FAIL;
	}
	memset(resource->recv_wr_arr, 0, size);

	VL_MEM_TRACE(("Finish allocating resources"));
	return SUCCESS;
}

static int init_hca(struct resources_t *resource)
{
	struct ibv_device *ib_dev = NULL;
	struct ibv_device **dev_list;
	int num_devices, i, rc;

	resource->hca_p = VL_MALLOC(sizeof(struct hca_data_t), struct hca_data_t);
	if (!resource->hca_p) {
		VL_MEM_ERR(("Fail to alloc hca_data_t"));
		exit(-1);
	}

	dev_list = ibv_get_device_list(&num_devices);
	if (!dev_list) {
		VL_MEM_ERR(("ibv_get_device_list failed"));
		exit(-1);
	}

	for (i = 0; i < num_devices; i++) {
		if (!strcmp(ibv_get_device_name(dev_list[i]), config.ib_dev)) {
			ib_dev = dev_list[i];
			break;
		}
	}

	if (!ib_dev) {
		VL_MEM_ERR(("HCA ID %s wasn't found in host",
				config.ib_dev));
		ibv_free_device_list(dev_list);
		return FAIL;
	}

	resource->hca_p->context = ibv_open_device(ib_dev);
	if (!resource->hca_p->context) {
		VL_MEM_ERR(("ibv_open_device with HCA ID %s failed",
				config.ib_dev));
		ibv_free_device_list(dev_list);
		return FAIL;
	}

	VL_MEM_TRACE1(("HCA %s was opened, context = %p",
			config.ib_dev, resource->hca_p->context));

	ibv_free_device_list(dev_list);

	rc = ibv_query_device(resource->hca_p->context, &resource->hca_p->device_attr);
	if (rc) {
		VL_MEM_ERR(("ibv_query_device failed"));
		return FAIL;
	}
	VL_MEM_TRACE1(("HCA was queried"));

	rc = ibv_query_port(resource->hca_p->context, IB_PORT, &resource->hca_p->port_attr);
	if (rc) {
		VL_MEM_ERR(("ibv_query_port failed"));
		return FAIL;
	}

	/* check that the port is in active state */
	if (resource->hca_p->port_attr.state != IBV_PORT_ACTIVE) {
		VL_MEM_ERR(("IB Port is not in active state"));
		return FAIL;
	}

	return SUCCESS;
}

static int init_pd(struct resources_t *resource)
{

	VL_MEM_TRACE1(("Going to create PD"));
	resource->pd = ibv_alloc_pd(resource->hca_p->context);

	if (!resource->pd) {
		VL_MEM_ERR(("Fail to create PD"));
		return FAIL;
	}

	VL_MEM_TRACE1(("Finish init PD"));
	return SUCCESS;
}

static int init_cq(struct resources_t *resource)
{
	resource->cq = 	ibv_create_cq(resource->hca_p->context, config.ring_depth, NULL, NULL, 0);
	if (!resource->cq) {
		VL_MEM_ERR(("Fail in ibv_create_cq"));
		return FAIL;
	}

	VL_MEM_TRACE1(("Finish init CQ"));

	return SUCCESS;
}

static int init_qp(struct resources_t *resource)
{
	struct ibv_qp_init_attr qp_init_attr;

	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.qp_type		= config.qp_type;
	qp_init_attr.sq_sig_all		= 1;
	qp_init_attr.recv_cq		= resource->cq;
	qp_init_attr.send_cq		= resource->cq;
	qp_init_attr.cap.max_recv_sge	= DEF_NUM_SGE;
	qp_init_attr.cap.max_recv_wr	= config.ring_depth;
	qp_init_attr.cap.max_send_sge	= DEF_NUM_SGE;
	qp_init_attr.cap.max_send_wr	= config.ring_depth;

	VL_MEM_TRACE1(("Going to create QP type %s, max_send_wr %d, max_send_sge %d ",
			VL_ibv_qp_type_str(config.qp_type),
			qp_init_attr.cap.max_send_wr,
			qp_init_attr.cap.max_send_sge));

	resource->qp = ibv_create_qp(resource->pd, &qp_init_attr);
	if (!resource->qp) {
		VL_MEM_ERR(("Fail to create QP"));
		return FAIL;
	}

	VL_MEM_TRACE1(("QP num 0x%x was created", resource->qp->qp_num));

	VL_MEM_TRACE1(("Finish init QP"));
	return SUCCESS;
}

static int init_mr(struct resources_t *resource)
{
	resource->mr->ibv_mr =
		ibv_reg_mr(resource->pd, resource->mr->addr,
			   config.msg_sz, IBV_ACCESS_LOCAL_WRITE);
	if (!resource->mr->ibv_mr) {
		VL_MEM_ERR(("Fail in ibv_reg_mr"));
		return FAIL;
	}

	VL_MEM_TRACE1(("MR created, addr = %p, size = %zu, lkey = 0x%x",
			resource->mr->ibv_mr->addr,
			resource->mr->ibv_mr->length,
			resource->mr->ibv_mr->lkey));

	VL_MEM_TRACE1(("Finish init MR"));

	return SUCCESS;
}

int init_resources(struct resources_t *resource)
{

	if (init_hca(resource) != SUCCESS ||
	    init_pd(resource) != SUCCESS ||
	    init_cq(resource) != SUCCESS ||
	    init_qp(resource) != SUCCESS ||
	    init_mr(resource) != SUCCESS){
			VL_MEM_ERR(("Fail to init resource"));
			return FAIL;
	}
	VL_MEM_TRACE(("Finish to initialize resources"));
	return SUCCESS;
}

static int destroy_all_mr(struct resources_t *resource)
{
	int rc;
	int result1 = SUCCESS;

	if (resource->mr) {
		if (resource->mr->ibv_mr) {
			VL_MEM_TRACE1(("Going to destroy MR"));
			rc = ibv_dereg_mr(resource->mr->ibv_mr);
			CHECK_VALUE("ibv_reg_mr", rc, 0, result1 = FAIL);
			VL_FREE(resource->mr->addr);
		}

		VL_FREE(resource->mr);
	}

	VL_MEM_TRACE1(("Finish destroy all MR"));
	return result1;
}

static int destroy_qp(struct resources_t *resource)
{
	int rc;

	if (!resource->qp)
		return SUCCESS;

	VL_MEM_TRACE1(("Going to destroy QP"));
	rc = ibv_destroy_qp(resource->qp);
	CHECK_VALUE("ibv_destroy_qp", rc, 0, return FAIL);

	VL_MEM_TRACE1(("Finish destroy QP"));

	return SUCCESS;
}


static int destroy_cq(struct resources_t *resource)
{
	int rc;

	if (!resource->cq)
		return SUCCESS;

	VL_MEM_TRACE1(("Going to destroy CQ"));
	rc = ibv_destroy_cq(resource->cq);
	CHECK_VALUE("ibv_destroy_cq", rc, 0, return FAIL);

	VL_MEM_TRACE1(("Finish destroy CQ"));

	return SUCCESS;
}

static int destroy_pd(struct resources_t *resource)
{
	int rc;

	if (!resource->pd)
		return SUCCESS;

	VL_MEM_TRACE1(("Going to dealloc_pd."));
	rc = ibv_dealloc_pd(resource->pd);
	if (rc) {
		VL_MEM_ERR(("Fail in ibv_dealloc_pd (%s)", strerror(rc)));
		return FAIL;

	}

	VL_MEM_TRACE1(("Finish destroy PD"));

	return SUCCESS;
}

static int destroy_hca(struct resources_t *resource)
{
	int rc;
	int result1 = SUCCESS;

	if (!resource->hca_p)
		return SUCCESS;

	if (!resource->hca_p->context)
		return SUCCESS;

	rc = ibv_close_device(resource->hca_p->context);
	if (rc) {
		VL_MEM_ERR(("Fail in ibv_close_device (%s)", strerror(rc)));
		result1 = FAIL;
	}

	VL_FREE(resource->hca_p);
	VL_MEM_TRACE1(("Finish destroy HCA"));
	return result1;
}

int destroy_resources(struct resources_t *resource)
{
	int result1 = SUCCESS;

	if (destroy_all_mr(resource) != SUCCESS ||
	    destroy_qp(resource) != SUCCESS ||
	    destroy_cq(resource) != SUCCESS ||
	    destroy_pd(resource) != SUCCESS ||
	    destroy_hca(resource) != SUCCESS)
		result1 = FAIL;

	if (resource->wc_arr)
		VL_FREE(resource->wc_arr);
	if (resource->send_wr_arr)
		VL_FREE(resource->send_wr_arr);
	if (resource->recv_wr_arr)
		VL_FREE(resource->recv_wr_arr);
	if (resource->sge_arr)
		VL_FREE(resource->sge_arr);

	VL_MEM_TRACE(("Finish to destroy all resources"));
	return result1;
}

static int qp_to_init(const struct resources_t *resource)
{
	struct ibv_qp_attr attr = {
		.qp_state        = IBV_QPS_INIT,
		.pkey_index      = 0,
		.port_num        = IB_PORT,
		.qp_access_flags = 0
	};

	if (ibv_modify_qp(resource->qp, &attr,
			  IBV_QP_STATE              |
			  IBV_QP_PKEY_INDEX         |
			  IBV_QP_PORT               |
			  IBV_QP_ACCESS_FLAGS)) {
		VL_MISC_ERR(("Fail to modify RC QP to IBV_QP_INIT"));
		return FAIL;
	}

	return SUCCESS;
}

static int qp_to_rtr(const struct resources_t *resource)
{
	struct sync_qp_info_t remote_qp = {0};
	struct sync_qp_info_t local_qp = {0};
	struct ibv_qp_attr attr = {
		.qp_state		= IBV_QPS_RTR,
		.path_mtu		= IBV_MTU_1024,
		.dest_qp_num		= remote_qp.qp_num,
		.rq_psn			= 0,
		.max_dest_rd_atomic	= 0,
		.min_rnr_timer		= 0x10,
		.ah_attr		= {
			.is_global	= 0,
			.dlid		= remote_qp.lid,
			.sl		= 0,
			.src_path_bits	= 0,
			.port_num	= IB_PORT,
			}
	};
	int rc;

	local_qp.qp_num = resource->qp->qp_num;
	local_qp.lid = resource->hca_p->port_attr.lid;

	if (!config.is_daemon) {
		rc = send_info(resource, &local_qp, sizeof(local_qp));
		if (rc)
			return FAIL;

		rc = recv_info(resource, &remote_qp, sizeof(remote_qp));
		if (rc)
			return FAIL;
	} else {
		rc = recv_info(resource, &remote_qp, sizeof(remote_qp));
		if (rc)
			return FAIL;

		rc = send_info(resource, &local_qp, sizeof(local_qp));
		if (rc)
			return FAIL;
	}

	VL_MISC_TRACE1(("Going to RC QP to lid 0x%x qp_num 0x%x",
			remote_qp.lid,
			remote_qp.qp_num));

	attr.dest_qp_num = remote_qp.qp_num;
	attr.ah_attr.dlid = remote_qp.lid;

	if (ibv_modify_qp(resource->qp, &attr,
		  IBV_QP_STATE              |
		  IBV_QP_AV                 |
		  IBV_QP_PATH_MTU           |
		  IBV_QP_DEST_QPN           |
		  IBV_QP_RQ_PSN             |
		  IBV_QP_MAX_DEST_RD_ATOMIC |
		  IBV_QP_MIN_RNR_TIMER)) {
		VL_MISC_ERR(("Fail to modify RC QP, to IBV_QPS_RTR"));
		return FAIL;
	}

	return SUCCESS;
}

static int qp_to_rts(const struct resources_t *resource)
{
	struct ibv_qp_attr attr = {
	.qp_state		= IBV_QPS_RTS,
	.timeout		= 0x10,
	.retry_cnt		= 7,
	.rnr_retry		= 7,
	.sq_psn			= 0,
	.max_rd_atomic		= 0
	};

	if (ibv_modify_qp(resource->qp, &attr,
		  IBV_QP_STATE              |
		  IBV_QP_TIMEOUT            |
		  IBV_QP_RETRY_CNT          |
		  IBV_QP_RNR_RETRY          |
		  IBV_QP_SQ_PSN             |
		  IBV_QP_MAX_QP_RD_ATOMIC)) {
		VL_MISC_ERR(("Fail to modify RC QP to IBV_QPS_RTS."));
		return FAIL;
	}

	VL_MISC_TRACE1(("RC QP qp_num 0x%x now at RTS.", resource->qp->qp_num));

	return SUCCESS;
}

int init_qps(struct resources_t *resource)
{
	if (qp_to_init(resource))
		return FAIL;

	if (qp_to_rtr(resource))
		return FAIL;

	if(!config.is_daemon) {
		if (qp_to_rts(resource))
			return FAIL;
	}

	VL_MISC_TRACE1(("QP qp_num 0x%x is ready to work", resource->qp->qp_num));

	VL_MISC_TRACE(("init_qps is done"));

	return  SUCCESS;
}

