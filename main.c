/*
 *
 * Copyright 2023 Kenichi Yasukata
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_bus_pci.h>
#include <rte_thash.h>

#define NUM_RX_DESC (128)
#define NUM_TX_DESC NUM_RX_DESC
#define NUM_NETSTACK_PB (8192)
#define NUM_NETSTACK_TCP_CONN (512)
#define ETH_RX_BATCH (32)
#define ETH_TX_BATCH (32)

static _Atomic uint8_t stat_idx = 0;

struct io_opaque {
	uint16_t portid;
	uint16_t queueid;
	struct {
		struct {
			struct rte_mbuf *m[ETH_TX_BATCH];
			uint16_t cnt;
		} tx;
	} eth;
	struct {
		struct {
			uint64_t rx_pkt;
			uint64_t rx_drop;
			uint64_t tx_pkt;
			uint64_t tx_fail;
		} eth;
	} stat[2];
};

static uint32_t ip4_addr_be[RTE_MAX_ETHPORTS];
static struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS] = { 0 };
static struct rte_eth_conf nic_conf[RTE_MAX_ETHPORTS] = { 0 };
static struct rte_mempool *pktmbuf_pool[RTE_MAX_LCORE] = { 0 };
static struct io_opaque io_opaque[RTE_MAX_LCORE][RTE_MAX_ETHPORTS] = { 0 };

static uint16_t helper_ip4_get_connection_affinity(uint16_t protocol, uint32_t local_ip4_be, uint16_t local_port_be, uint32_t peer_ip4_be, uint16_t peer_port_be, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	{
		uint8_t is_supported = 0;
		switch (protocol) {
		case 6: /* tcp */
			if (nic_conf[iop->portid].rx_adv_conf.rss_conf.rss_hf & RTE_ETH_RSS_TCP)
				is_supported = 1;
			break;
		case 17: /* upd */
			if (nic_conf[iop->portid].rx_adv_conf.rss_conf.rss_hf & RTE_ETH_RSS_UDP)
				is_supported = 1;
			break;
		default:
			break;
		}
		if (!is_supported)
			return UINT16_MAX;
	}
	{
		struct rte_eth_dev_info dev_info = { 0 };
		assert(rte_eth_dev_info_get(iop->portid, &dev_info) >= 0);

		uint8_t rss_key_buf[255] = { 0 };
		struct rte_eth_rss_conf rss_conf = { .rss_key = rss_key_buf, .rss_key_len = sizeof(rss_key_buf), };
		assert(!rte_eth_dev_rss_hash_conf_get(iop->portid, &rss_conf));

		struct rte_eth_rss_reta_entry64 reta_conf[8] = {
			{ .mask = 0xffffffffffffffff, },
			{ .mask = 0xffffffffffffffff, },
			{ .mask = 0xffffffffffffffff, },
			{ .mask = 0xffffffffffffffff, },
			{ .mask = 0xffffffffffffffff, },
			{ .mask = 0xffffffffffffffff, },
			{ .mask = 0xffffffffffffffff, },
			{ .mask = 0xffffffffffffffff, },
		};
		assert(dev_info.reta_size <= 512);
		assert(!rte_eth_dev_rss_reta_query(iop->portid, reta_conf, dev_info.reta_size));

		{
			struct rte_ipv4_tuple input_tuple = {
				.src_addr = ntohl(peer_ip4_be),
				.dst_addr = ntohl(local_ip4_be),
				.dport = ntohs(local_port_be),
				.sport = ntohs(peer_port_be),
			};
			uint32_t idx = rte_softrss((uint32_t *) &input_tuple, RTE_THASH_V4_L4_LEN, rss_conf.rss_key) & ((1 << (31 - __builtin_clz(dev_info.reta_size))) - 1) /* lsb */;
			return reta_conf[idx / RTE_ETH_RETA_GROUP_SIZE].reta[idx % RTE_ETH_RETA_GROUP_SIZE];
		}
	}
}

static uint16_t iip_ops_l2_hdr_len(void *pkt, void *opaque)
{
	{/* unused */
		(void) pkt;
		(void) opaque;
	}
	return sizeof(struct rte_ether_hdr);
}

static uint8_t *iip_ops_l2_hdr_src_ptr(void *pkt, void *opaque)
{
	return ((struct rte_ether_hdr *)(iip_ops_pkt_get_data(pkt, opaque)))->src_addr.addr_bytes;
}

static uint8_t *iip_ops_l2_hdr_dst_ptr(void *pkt, void *opaque)
{
	return ((struct rte_ether_hdr *)(iip_ops_pkt_get_data(pkt, opaque)))->dst_addr.addr_bytes;
}

static uint8_t iip_ops_l2_skip(void *pkt, void *opaque)
{
	{/* unused */
		(void) pkt;
		(void) opaque;
	}
	return 0;
}

static uint16_t iip_ops_l2_ethertype_be(void *pkt, void *opaque)
{
	return ((struct rte_ether_hdr *)(iip_ops_pkt_get_data(pkt, opaque)))->ether_type;
}

static uint16_t iip_ops_l2_addr_len(void *opaque)
{
	{/* unused */
		(void) opaque;
	}
	return 6;
}

static void iip_ops_l2_broadcast_addr(uint8_t bc_mac[], void *opaque)
{
	{/* unused */
		(void) opaque;
	}
	memset(bc_mac, 0xff, 6);
}

static void iip_ops_l2_hdr_craft(void *pkt, uint8_t src[], uint8_t dst[], uint16_t ethertype_be, void *opaque)
{
	struct rte_ether_hdr *ethh = (struct rte_ether_hdr *) iip_ops_pkt_get_data(pkt, opaque);
	memcpy(ethh->src_addr.addr_bytes, src, 6);
	memcpy(ethh->dst_addr.addr_bytes, dst, 6);
	ethh->ether_type = ethertype_be;
}

static uint8_t iip_ops_arp_lhw(void *opaque)
{
	{/* unused */
		(void) opaque;
	}
	return 6;
}

static uint8_t iip_ops_arp_lproto(void *opaque)
{
	{/* unused */
		(void) opaque;
	}
	return 4;
}

static void *iip_ops_pkt_alloc(void *opaque __attribute__((unused)))
{
	assert(pktmbuf_pool[rte_socket_id_by_idx(rte_lcore_to_socket_id(rte_lcore_id()))]);
	return rte_pktmbuf_alloc(pktmbuf_pool[rte_socket_id_by_idx(rte_lcore_to_socket_id(rte_lcore_id()))]);
}

static void iip_ops_pkt_free(void *pkt, void *opaque __attribute__((unused)))
{
	rte_pktmbuf_free((struct rte_mbuf *) pkt);
}

static void *iip_ops_pkt_get_data(void *pkt, void *opaque __attribute__((unused)))
{
	return rte_pktmbuf_mtod((struct rte_mbuf *) pkt, void *);
}

static uint16_t iip_ops_pkt_get_len(void *pkt, void *opaque __attribute__((unused)))
{
	return rte_pktmbuf_data_len((struct rte_mbuf *) pkt);
}

static void iip_ops_pkt_set_len(void *pkt, uint16_t len, void *opaque __attribute__((unused)))
{
	assert(pkt);
	rte_pktmbuf_data_len((struct rte_mbuf *) pkt) = len;
}

static void iip_ops_pkt_increment_head(void *pkt, uint16_t len, void *opaque __attribute__((unused)))
{
	assert(pkt);
	rte_pktmbuf_adj((struct rte_mbuf *) pkt, len);
}

static void iip_ops_pkt_decrement_tail(void *pkt, uint16_t len, void *opaque __attribute__((unused)))
{
	assert(pkt);
	rte_pktmbuf_trim((struct rte_mbuf *) pkt, len);
}

static void *iip_ops_pkt_clone(void *pkt, void *opaque __attribute__((unused)))
{
	assert(pktmbuf_pool[rte_socket_id_by_idx(rte_lcore_to_socket_id(rte_lcore_id()))]);
	assert(pkt);
	return rte_pktmbuf_clone((struct rte_mbuf *) pkt, pktmbuf_pool[rte_socket_id_by_idx(rte_lcore_to_socket_id(rte_lcore_id()))]);
}

static void iip_ops_pkt_scatter_gather_chain_append(void *pkt_head, void *pkt_tail, void *opaque __attribute__((unused)))
{
	assert(!rte_pktmbuf_chain((struct rte_mbuf *) pkt_head, (struct rte_mbuf *) pkt_tail));
}

static void *iip_ops_pkt_scatter_gather_chain_get_next(void *pkt_head, void *opaque __attribute__((unused)))
{
	return ((struct rte_mbuf *) pkt_head)->next;
}

static uint16_t iip_ops_util_core(void)
{
	return rte_lcore_index(rte_lcore_id());
}

static void iip_ops_util_now_ns(uint32_t t[3])
{
	struct timespec ts;
	assert(!clock_gettime(CLOCK_REALTIME, &ts));
	t[0] = (ts.tv_sec >> 32) & 0xffffffff;
	t[1] = (ts.tv_sec >>  0) & 0xffffffff;
	t[2] = ts.tv_nsec;
}

static void iip_ops_l2_flush(void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	if (iop->eth.tx.cnt) {
		uint16_t cnt = rte_eth_tx_burst(iop->portid, iop->queueid, iop->eth.tx.m, rte_eth_tx_prepare(iop->portid, iop->queueid, iop->eth.tx.m, iop->eth.tx.cnt));
		if (cnt != iop->eth.tx.cnt) {
			//printf("tx failed: %u %u\n", cnt, iop->eth.tx.cnt);
			{
				struct rte_eth_stats s;
				assert(!rte_eth_stats_get(iop->portid, &s));
				if (s.oerrors) {
					printf("output error %lu\n", s.oerrors);
					assert(!rte_eth_stats_reset(iop->portid));
				}
			}
			{
				uint16_t i;
				for (i = cnt; i < iop->eth.tx.cnt; i++)
					rte_pktmbuf_free(iop->eth.tx.m[i]);
			}
		}
		iop->stat[stat_idx].eth.tx_pkt += cnt;
		iop->stat[stat_idx].eth.tx_fail += iop->eth.tx.cnt - cnt;
		iop->eth.tx.cnt = 0;
	}
}

static void iip_ops_l2_push(void *_m, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	rte_pktmbuf_pkt_len((struct rte_mbuf *) _m) = 0;
	{
		struct rte_mbuf *m = (struct rte_mbuf *) _m;
		while (m) {
			rte_pktmbuf_pkt_len((struct rte_mbuf *) _m) += rte_pktmbuf_data_len(m);
			m = m->next;
		}
	}
	iop->eth.tx.m[iop->eth.tx.cnt++] = (struct rte_mbuf *) _m;
	if (iop->eth.tx.cnt == ETH_TX_BATCH)
		iip_ops_l2_flush(opaque);
}

static uint8_t iip_ops_nic_feature_offload_tx_scatter_gather(void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	return (nic_conf[iop->portid].txmode.offloads & RTE_ETH_TX_OFFLOAD_MULTI_SEGS ? 1 : 0);
}

static uint8_t iip_ops_nic_feature_offload_rx_checksum(void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	return (nic_conf[iop->portid].rxmode.offloads & RTE_ETH_RX_OFFLOAD_CHECKSUM ? 1 : 0);
}

static uint8_t iip_ops_nic_feature_offload_ip4_rx_checksum(void *opaque)
{
	return iip_ops_nic_feature_offload_rx_checksum(opaque);
}

static uint8_t iip_ops_nic_feature_offload_ip4_tx_checksum(void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	return (nic_conf[iop->portid].txmode.offloads & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM ? 1 : 0);
}

static uint8_t iip_ops_nic_offload_ip4_rx_checksum(void *m, void *opaque __attribute__((unused)))
{
	return ((((struct rte_mbuf *) m)->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_GOOD) ? 1 : 0);
}

static uint8_t iip_ops_nic_offload_tcp_rx_checksum(void *m, void *opaque __attribute__((unused)))
{
	return ((((struct rte_mbuf *) m)->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_GOOD) ? 1 : 0);
}

static uint8_t iip_ops_nic_offload_udp_rx_checksum(void *m, void *opaque __attribute__((unused)))
{
	return iip_ops_nic_offload_tcp_rx_checksum(m, opaque);
}

static void iip_ops_nic_offload_ip4_tx_checksum_mark(void *m, void *opaque __attribute__((unused)))
{
	((struct rte_mbuf *) m)->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
	((struct rte_mbuf *) m)->l2_len = sizeof(struct rte_ether_hdr);
	((struct rte_mbuf *) m)->l3_len = PB_IP4(rte_pktmbuf_mtod((struct rte_mbuf *) m, uint8_t *))->l * 4;
}

static uint8_t iip_ops_nic_feature_offload_tcp_rx_checksum(void *opaque)
{
	return iip_ops_nic_feature_offload_rx_checksum(opaque);
}

static uint8_t iip_ops_nic_feature_offload_tcp_tx_checksum(void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	return (nic_conf[iop->portid].txmode.offloads & RTE_ETH_TX_OFFLOAD_TCP_CKSUM ? 1 : 0);
}

static uint8_t iip_ops_nic_feature_offload_tcp_tx_tso(void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	return (nic_conf[iop->portid].txmode.offloads & RTE_ETH_TX_OFFLOAD_TCP_TSO ? 1 : 0);
}

static void iip_ops_nic_offload_tcp_tx_checksum_mark(void *m, void *opaque __attribute__((unused)))
{
	((struct rte_mbuf *) m)->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
}

static void iip_ops_nic_offload_tcp_tx_tso_mark(void *m, void *opaque)
{
	if (1500 - PB_IP4(rte_pktmbuf_mtod((struct rte_mbuf *) m, uint8_t *))->l * 4 - PB_TCP(rte_pktmbuf_mtod((struct rte_mbuf *) m, uint8_t *))->doff * 4 < PB_TCP_PAYLOAD_LEN(rte_pktmbuf_mtod((struct rte_mbuf *) m, uint8_t *))) {
		((struct rte_mbuf *) m)->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;
		((struct rte_mbuf *) m)->l4_len = PB_TCP(rte_pktmbuf_mtod((struct rte_mbuf *) m, uint8_t *))->doff * 4;
		assert(((struct rte_mbuf *) m)->ol_flags == (RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_TCP_CKSUM | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4));
		assert(((struct rte_mbuf *) m)->l2_len == sizeof(struct rte_ether_hdr));
		assert(((struct rte_mbuf *) m)->l3_len == PB_IP4(rte_pktmbuf_mtod((struct rte_mbuf *) m, uint8_t *))->l * 4);
		((struct rte_mbuf *) m)->tso_segsz = 1500 - PB_IP4(rte_pktmbuf_mtod((struct rte_mbuf *) m, uint8_t *))->l * 4 - PB_TCP(rte_pktmbuf_mtod((struct rte_mbuf *) m, uint8_t *))->doff * 4;
	}
}

static uint8_t iip_ops_nic_feature_offload_udp_rx_checksum(void *opaque)
{
	return iip_ops_nic_feature_offload_rx_checksum(opaque);
}

static uint8_t iip_ops_nic_feature_offload_udp_tx_checksum(void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	return (nic_conf[iop->portid].txmode.offloads & RTE_ETH_TX_OFFLOAD_UDP_CKSUM ? 1 : 0);
}

static uint8_t iip_ops_nic_feature_offload_udp_tx_tso(void *opaque __attribute__((unused)))
{
	void **opaque_array = (void **) opaque;
	struct io_opaque *iop = (struct io_opaque *) opaque_array[0];
	return (nic_conf[iop->portid].txmode.offloads & RTE_ETH_TX_OFFLOAD_UDP_TSO ? 1 : 0);
}

static void iip_ops_nic_offload_udp_tx_checksum_mark(void *m, void *opaque __attribute__((unused)))
{
	((struct rte_mbuf *) m)->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
}

static void iip_ops_nic_offload_udp_tx_tso_mark(void *m, void *opaque __attribute__((unused)))
{
	if (1500 - PB_IP4(rte_pktmbuf_mtod((struct rte_mbuf *) m, uint8_t *))->l * 4 - sizeof(struct iip_udp_hdr) < PB_UDP_PAYLOAD_LEN(rte_pktmbuf_mtod((struct rte_mbuf *) m, uint8_t *))) {
		((struct rte_mbuf *) m)->ol_flags |= RTE_MBUF_F_TX_UDP_SEG;
		((struct rte_mbuf *) m)->l4_len = sizeof(struct iip_udp_hdr);
		((struct rte_mbuf *) m)->tso_segsz = 1500 - PB_IP4(rte_pktmbuf_mtod((struct rte_mbuf *) m, uint8_t *))->l * 4 - sizeof(struct iip_udp_hdr);
	}
}

/* thread loop */
static int lcore_thread_fn(void *__unused __attribute__((unused)))
{
	{ /* set queue id */
		uint16_t portid;
		RTE_ETH_FOREACH_DEV(portid) {
			io_opaque[rte_lcore_index(rte_lcore_id())][portid].portid = portid;
			io_opaque[rte_lcore_index(rte_lcore_id())][portid].queueid = rte_lcore_index(rte_lcore_id());
		}
	}
	{
		void *workspace = rte_zmalloc(NULL, iip_workspace_size(), 8);
		assert(workspace);
		{ /* allocate and associate memory for packet representation structure */
			uint32_t i;
			for (i = 0; i < NUM_NETSTACK_PB; i++) {
				void *p = rte_zmalloc(NULL, iip_pb_size(), 8);
				assert(p);
				iip_add_pb(workspace, p);
			}
		}
		{ /* allocate and associate memory for  tcp connection */
			uint16_t i;
			for (i = 0; i < NUM_NETSTACK_TCP_CONN; i++) {
				void *conn = rte_zmalloc(NULL, iip_tcp_conn_size(), 8);
				assert(conn);
				iip_add_tcp_conn(workspace, conn);
			}
		}
		{ /* call app thread init */
			void *opaque[2] = { &io_opaque[rte_lcore_index(rte_lcore_id())], NULL, };
			{
				opaque[1] = __app_thread_init(workspace, opaque); /* TODO: for every port? */
				{
					uint64_t prev_print = 0;
					do {
						uint32_t next_us = 1000000U; /* 1 sec */
						{
							uint16_t portid;
							RTE_ETH_FOREACH_DEV(portid) {
								opaque[0] = (void *) &io_opaque[rte_lcore_index(rte_lcore_id())][portid];
								{
									uint32_t _next_us = 0;
									struct rte_mbuf *m[ETH_RX_BATCH];
									uint16_t cnt = rte_eth_rx_burst(portid, rte_lcore_index(rte_lcore_id()), m, ETH_RX_BATCH);
									io_opaque[rte_lcore_index(rte_lcore_id())][portid].stat[stat_idx].eth.rx_pkt += cnt;
									iip_run(workspace, ports_eth_addr[portid].addr_bytes,
											ip4_addr_be[portid], (void **) m, cnt, &_next_us, opaque);
									next_us = _next_us < next_us ? _next_us : next_us;
								}
								{
									uint32_t _next_us = 0;
									__app_loop(ports_eth_addr[portid].addr_bytes, ip4_addr_be[portid], &_next_us, opaque);
									next_us = _next_us < next_us ? _next_us : next_us;
								}
							}
						}
						if (!rte_lcore_index(rte_lcore_id())) {
							struct timespec ts;
							assert(!clock_gettime(CLOCK_REALTIME, &ts));
							if (prev_print + 1000000000UL < ts.tv_sec * 1000000000UL + ts.tv_nsec) {
#if 0
								stat_idx = (stat_idx ? 0 : 1);
								asm volatile ("" ::: "memory");
								{
									uint16_t portid;
									RTE_ETH_FOREACH_DEV(portid) {
										{
											uint64_t total_rx = 0, total_tx = 0;
											struct rte_eth_stats s;
											assert(!rte_eth_stats_get(portid, &s));
											assert(!rte_eth_stats_reset(portid));
											{
												uint16_t i;
												for (i = 0; i < rte_lcore_count(); i++) {
													printf("\x1b[33mport[%u]:queue[%u]: rx %lu drop %lu tx %lu fail %lu (rx-error %lu, rx-nobuf %lu tx-error %lu)\n\x1b[39m",
															portid, i,
															io_opaque[i][portid].stat[stat_idx ? 0 : 1].eth.rx_pkt,
															io_opaque[i][portid].stat[stat_idx ? 0 : 1].eth.rx_drop,
															io_opaque[i][portid].stat[stat_idx ? 0 : 1].eth.tx_pkt,
															io_opaque[i][portid].stat[stat_idx ? 0 : 1].eth.tx_fail,
															s.ierrors,
															s.rx_nombuf,
															s.oerrors);
													total_rx += io_opaque[i][portid].stat[stat_idx ? 0 : 1].eth.rx_pkt;
													total_tx += io_opaque[i][portid].stat[stat_idx ? 0 : 1].eth.tx_pkt;
													memset(&io_opaque[i][portid].stat[stat_idx ? 0 : 1], 0, sizeof(io_opaque[i][portid].stat[stat_idx ? 0 : 1]));
												}
											}
											printf("\x1b[33meth total: rx %lu tx %lu\n\x1b[39m", total_rx, total_tx);
										}
									}
								}
#endif
								prev_print = ts.tv_sec * 1000000000UL + ts.tv_nsec;
							}
						}
					} while (!__app_should_stop(opaque));
				}
			}
		}
	}
	return 0;
}

static int __iosub_main(int argc, char *const *argv)
{
	{ /* dpdk init */
		int ret;
		assert((ret = rte_eal_init(argc, (char **) argv)) >= 0);
		argc -= ret;
		argv += ret;
	}

	assert(0 < rte_eth_dev_count_avail());

	{
		uint32_t num_socket = rte_socket_count();
		{
			uint32_t i;
			for (i = 0; i < num_socket; i++) {
				printf("create mbuf pool for socket %u\n", i);
				{
					char mempool_name[32] = { 0 };
					snprintf(mempool_name, sizeof(mempool_name), "mem-%u", i);
					assert((pktmbuf_pool[i] = rte_pktmbuf_pool_create(mempool_name,
									RTE_MAX(rte_eth_dev_count_avail() * rte_lcore_count() * (NUM_RX_DESC + NUM_TX_DESC) * 2, 8192U),
									512, 0,
									0xffff /* large buffer */,
									rte_socket_id_by_idx(i))) != NULL);
				}
			}
		}
	}

	{ /* dpdk interface init */
		uint32_t num_queue = rte_lcore_count();
		{
			uint16_t portid;
			RTE_ETH_FOREACH_DEV(portid) {
				uint16_t nb_rxd = NUM_RX_DESC;
				uint16_t nb_txd = NUM_TX_DESC;
				struct rte_eth_dev_info dev_info = { 0 };
				assert(rte_eth_dev_info_get(portid, &dev_info) >= 0);

				printf("driver: %s\n", dev_info.driver_name);
				printf("max queue rx %u tx %u\n", dev_info.max_rx_queues, dev_info.max_tx_queues);
				assert(num_queue < dev_info.max_rx_queues);
				assert(num_queue < dev_info.max_tx_queues);
				printf("MTU: min %u max %u\n", dev_info.min_mtu, dev_info.max_mtu);
				assert(nic_conf[portid].rxmode.max_lro_pkt_size < dev_info.max_mtu);

				nic_conf[portid].rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
				nic_conf[portid].txmode.mq_mode = RTE_ETH_MQ_TX_NONE;

				if (!strncmp(dev_info.driver_name, "net_tap", strlen("net_tap")))
					printf("we do not employ offloading features of a tap device\n");
				else {
					{
						printf("RSS TCP: ");
						if (dev_info.flow_type_rss_offloads & RTE_ETH_RSS_TCP) {
							nic_conf[portid].rx_adv_conf.rss_conf.rss_hf |= RTE_ETH_RSS_TCP & dev_info.flow_type_rss_offloads;
							printf("ok (nic feature %lx tcp-rss-all %lx)\n", dev_info.flow_type_rss_offloads, RTE_ETH_RSS_TCP);
						} else printf("no\n"); /* TODO: software-based RSS */
					}
					{
						printf("RSS UDP: ");
						if (dev_info.flow_type_rss_offloads & RTE_ETH_RSS_UDP) {
							nic_conf[portid].rx_adv_conf.rss_conf.rss_hf |= RTE_ETH_RSS_UDP & dev_info.flow_type_rss_offloads;
							printf("ok (nic feature %lx udp-rss-all %lx)\n", dev_info.flow_type_rss_offloads, RTE_ETH_RSS_TCP);
						} else printf("no\n"); /* TODO: software-based RSS */
					}
					{
						printf("RX checksum: ");
						if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_CHECKSUM) {
							nic_conf[portid].rxmode.offloads |= RTE_ETH_RX_OFFLOAD_CHECKSUM;
							printf("ok\n");
						} else printf("no\n");
					}
					{
						printf("RX LRO: ");
						if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO) {
							nic_conf[portid].rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TCP_LRO;
							nic_conf[portid].rxmode.max_lro_pkt_size = dev_info.max_lro_pkt_size;
							printf("ok (max lro pkt size %u)\n", nic_conf[portid].rxmode.max_lro_pkt_size);
						} else printf("no\n");
					}
					{
						printf("TX multi-seg: ");
						if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS) {
							nic_conf[portid].txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
							printf("ok\n");
						} else printf("no\n");
					}
					{
						printf("TX IPv4 checksum: ");
						if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) {
							nic_conf[portid].txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
							printf("ok\n");
						} else printf("no\n");
					}
					{
						printf("TX TCP checksum: ");
						if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) {
							nic_conf[portid].txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
							printf("ok\n");
						} else printf("no\n");
					}
					{
						printf("TX TCP TSO: ");
						if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO) {
							nic_conf[portid].txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_TSO;
							printf("ok\n");
						} else printf("no\n");
					}
					{
						printf("TX UDP checksum: ");
						if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) {
							nic_conf[portid].txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
							printf("ok\n");
						} else printf("no\n");
					}
					{
						printf("TX UDP TSO: ");
						if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_TSO) {
							nic_conf[portid].txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_TSO;
							printf("ok\n");
						} else printf("no\n");
					}
				}

				assert(rte_eth_dev_configure(portid, num_queue, num_queue, &nic_conf[portid]) >= 0);
				assert(rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd) >= 0);

				printf("configuring port %u with %d queues (tx %u rx %u)\n", portid, num_queue, nb_txd, nb_rxd);
				{
					uint16_t i;
					for (i = 0; i < num_queue; i++) {
						assert(rte_eth_rx_queue_setup(portid, i, nb_rxd,
									rte_eth_dev_socket_id(portid),
									&dev_info.default_rxconf,
									pktmbuf_pool[rte_socket_id_by_idx(rte_lcore_to_socket_id(i))]) >= 0);
						assert(rte_eth_tx_queue_setup(portid, i, nb_txd,
									rte_eth_dev_socket_id(portid),
									&dev_info.default_txconf) >= 0);
					}
				}
				/* start interface */
				assert(rte_eth_dev_start(portid) >= 0);
				assert(rte_eth_promiscuous_enable(portid) >= 0);

				/* obtain mac addr */
				assert(rte_eth_macaddr_get(portid, &ports_eth_addr[portid]) >= 0);
			}
		}
	}

	{ /* parse arguments */
		int ch;
		while ((ch = getopt(argc, argv, "a:")) != -1) {
			switch (ch) {
				case 'a':
					{ /* format: portid,address (e.g., 1,192.168.0.1 */
						char tmpbuf[64] = { 0 };
						size_t l = strlen(optarg);
						assert(l < (sizeof(tmpbuf) - 1));
						memcpy(tmpbuf, optarg, l);
						{
							size_t i;
							for (i = 0; i < l; i++) {
								if (tmpbuf[i] == ',') {
									tmpbuf[i] = '\0';
									break;
								}
							}
							assert(i != 0 && i != l);
							{
								uint16_t portid = atoi(&tmpbuf[0]);
								assert(portid < RTE_MAX_ETHPORTS);
								assert(inet_pton(AF_INET, &tmpbuf[i + 1], &ip4_addr_be[portid]) == 1);
								printf("port[%u]: local ip %u.%u.%u.%u\n",
										portid,
										(ip4_addr_be[portid] >>  0) & 0x0ff,
										(ip4_addr_be[portid] >>  8) & 0x0ff,
										(ip4_addr_be[portid] >> 16) & 0x0ff,
										(ip4_addr_be[portid] >> 24) & 0x0ff);
							}
						}
					}
					break;
				default:
					assert(0);
					break;
			}
		}
	}

	__app_init(argc, argv);

	rte_eal_mp_remote_launch(lcore_thread_fn, NULL, CALL_MAIN); /* start worker threads */

	{ /* wait for threads */
		unsigned lcore_id;
		RTE_LCORE_FOREACH_WORKER(lcore_id)
			assert(!rte_eal_wait_lcore(lcore_id));
	}

	{ /* stop */
		uint16_t portid;
		RTE_ETH_FOREACH_DEV(portid) {
			printf("Stopping port %u ... ", portid); fflush(stdout);
			assert(!rte_eth_dev_stop(portid));
			rte_eth_dev_close(portid);
			printf("OK\n");
		}
	}

	rte_eal_cleanup();

	return 0;
}
