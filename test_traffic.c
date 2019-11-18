#include <vl.h>
#include "types.h"

extern struct config_t config;

static inline void set_send_wr(struct resources_t *resource,
			       struct ibv_send_wr *wr, uint16_t size)
{
	int i;

	for (i = 0; i < size; i++) {
		wr[i].wr_id = WR_ID;
		wr[i].opcode = IBV_WR_SEND;
		wr[i].next = &wr[i + 1];
		wr[i].sg_list = &resource->sge_arr[i];
		wr[i].num_sge = DEF_NUM_SGE;

		resource->sge_arr[i].addr = (uintptr_t) resource->mr->addr;
		resource->sge_arr[i].length = config.msg_sz;
		resource->sge_arr[i].lkey = resource->mr->ibv_mr->lkey;
	}

	wr[size - 1].next = NULL;
}

static inline void set_recv_wr(struct resources_t *resource,
			       struct ibv_recv_wr *wr, uint16_t size)
{
	int i;

	for (i = 0; i < size; i++) {
		wr[i].wr_id = WR_ID;
		wr[i].next = &wr[i + 1];
		wr[i].sg_list = &resource->sge_arr[i];
		wr[i].num_sge = DEF_NUM_SGE;

		resource->sge_arr[i].addr = (uintptr_t) resource->mr->addr;
		resource->sge_arr[i].length = config.msg_sz;
		resource->sge_arr[i].lkey = resource->mr->ibv_mr->lkey;
	}

	wr[size - 1].next = NULL;
}

static inline void fast_set_recv_wr(struct ibv_recv_wr *wr, uint16_t size)
{
	int i;

	wr[size - 1].next = NULL;

	for (i = 0; i < size - 1; i++)
		wr[i].next = &wr[i + 1];
}

int prepare_receiver(struct resources_t *resource)
{
	int i;

	set_recv_wr(resource, resource->recv_wr_arr, 1);

	for (i = 0; i < (int) config.ring_depth; i++) {
		struct ibv_recv_wr *bad_wr = NULL;
		int rc;

		rc = ibv_post_recv(resource->qp, resource->recv_wr_arr, &bad_wr);
		if (rc) {
			VL_MISC_ERR(("in ibv_post_receive (%s)", strerror(rc)));
			return FAIL;
		}
	}

	set_recv_wr(resource, resource->recv_wr_arr, config.batch_size);

	return SUCCESS;
}

static int do_sender(struct resources_t *resource, uint32_t iters)
{
	uint32_t tot_ccnt = 0;
	uint32_t tot_scnt = 0;
	int result = SUCCESS;

	while (tot_ccnt < iters) {
		uint16_t outstanding = tot_scnt - tot_ccnt;
		int rc = 0;

		if ((tot_scnt < iters) && (outstanding < config.ring_depth)) {
			struct ibv_send_wr *bad_wr = NULL;
			uint32_t left = iters - tot_scnt;
			uint16_t batch;

			batch = (config.ring_depth - outstanding) >= config.batch_size ?
				(left >= config.batch_size ? config.batch_size : 1) : 1 ;

			set_send_wr(resource, resource->send_wr_arr, batch);

			rc = ibv_post_send(resource->qp, resource->send_wr_arr, &bad_wr);
			if (rc) {
				VL_MISC_ERR(("in ibv_post_send (%s)", strerror(rc)));
				result = FAIL;
				goto out;
			}

			tot_scnt += batch;
		}

		rc = ibv_poll_cq(resource->cq, config.batch_size, resource->wc_arr);

		if (rc > 0) {
			int i;

			for (i = 0; i < rc; i++)
				if (resource->wc_arr[i].status != IBV_WC_SUCCESS) {
					VL_MISC_ERR(("got WC with error (%d)", resource->wc_arr[i].status));
					result = FAIL;
					goto out;
				}

			tot_ccnt += rc;
		} else if (rc < 0) {
			VL_MISC_ERR(("in ibv_poll_cq (%s)", strerror(rc)));
			result = FAIL;
			goto out;
		}
	}

out:
	VL_MISC_TRACE(("Sender exit with tot_scnt=%u tot_ccnt=%u", tot_scnt, tot_ccnt));

	return result;
}

static int do_receiver(struct resources_t *resource, uint32_t iters)
{
	uint32_t tot_ccnt = 0;
	uint32_t tot_rcnt = config.ring_depth; //Due to pre-preparation of the RX
	int result = SUCCESS;

	while (tot_ccnt < iters) {
		uint16_t outstanding;
		int rc = 0;

		rc = ibv_poll_cq(resource->cq, config.batch_size, resource->wc_arr);

		if (rc > 0) {
			int i;

			for (i = 0; i < rc; i++)
				if (resource->wc_arr[i].status != IBV_WC_SUCCESS) {
					VL_MISC_ERR(("got WC with error (%d)", resource->wc_arr[i].status));
					result = FAIL;
					goto out;
				}

			tot_ccnt += rc;
		} else if (rc < 0) {
			VL_MISC_ERR(("in ibv_poll_cq (%s)", strerror(rc)));
			result = FAIL;
			goto out;
		}

		outstanding = tot_rcnt - tot_ccnt;

		if ((tot_rcnt < iters) && (outstanding < config.ring_depth)) {
			struct ibv_recv_wr *bad_wr = NULL;
			uint32_t left = iters - tot_rcnt;
			uint16_t batch;

			batch = (config.ring_depth - outstanding) >= config.batch_size ?
				(left >= config.batch_size ? config.batch_size : 1) : 1 ;

			fast_set_recv_wr(resource->recv_wr_arr, batch);

			rc = ibv_post_recv(resource->qp, resource->recv_wr_arr, &bad_wr);
			if (rc) {
				VL_MISC_ERR(("in ibv_post_receive (%s)", strerror(rc)));
				result = FAIL;
				goto out;
			}

			tot_rcnt += batch;
		}
	}

out:
	VL_MISC_TRACE(("Receiver exit with tot_rcnt=%u tot_ccnt=%u", tot_rcnt, tot_ccnt));

	return result;
}

int test_traffic(struct resources_t *resource, uint32_t iters)
{
	int rc;

	if (!config.is_daemon) {
		VL_MISC_TRACE(("Run sender"));

		if (VL_sock_sync_ready(&resource->sock)) {
			VL_SOCK_ERR(("Sync before traffic"));
			return FAIL;
		}

		if (do_sender(resource, iters))
			return FAIL;
	} else {
		rc = prepare_receiver(resource);
		if (rc)
			return FAIL;

		VL_MISC_TRACE(("Run receiver"));

		if (VL_sock_sync_ready(&resource->sock)) {
			VL_SOCK_ERR(("Sync before traffic"));
			return FAIL;
		}

		if (do_receiver(resource, iters))
			return FAIL;
	}

	return SUCCESS;
}

