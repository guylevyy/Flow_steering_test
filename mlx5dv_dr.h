#ifndef MLX5DV_DR_H
#define MLX5DV_DR_H

#define u8 uint8_t

enum dr_matcher_criteria {
	DR_MATCHER_CRITERIA_EMPTY	= 0,
	DR_MATCHER_CRITERIA_OUTER	= 1 << 0,
	DR_MATCHER_CRITERIA_MISC	= 1 << 1,
	DR_MATCHER_CRITERIA_INNER	= 1 << 2,
	DR_MATCHER_CRITERIA_MISC2	= 1 << 3,
	DR_MATCHER_CRITERIA_MISC3	= 1 << 4,
	DR_MATCHER_CRITERIA_MAX		= 1 << 5,
};

struct dr_match_spec {
	uint32_t smac_47_16;	/* Source MAC address of incoming packet */
	uint32_t ethertype:16;	/* Incoming packet Ethertype - this is the Ethertype following the last ;VLAN tag of the packet */
	uint32_t smac_15_0:16;	/* Source MAC address of incoming packet */
	uint32_t dmac_47_16;	/* Destination MAC address of incoming packet */
	uint32_t first_vid:12;	/* VLAN ID of first VLAN tag in the incoming packet. Valid only ;when cvlan_tag==1 or svlan_tag==1 */
	uint32_t first_cfi:1;	/* CFI bit of first VLAN tag in the incoming packet. Valid only when ;cvlan_tag==1 or svlan_tag==1 */
	uint32_t first_prio:3;	/* Priority of first VLAN tag in the incoming packet. Valid only when ;cvlan_tag==1 or svlan_tag==1 */
	uint32_t dmac_15_0:16;	/* Destination MAC address of incoming packet */
	uint32_t tcp_flags:9;	/* TCP flags. ;Bit 0: FIN;Bit 1: SYN;Bit 2: RST;Bit 3: PSH;Bit 4: ACK;Bit 5: URG;Bit 6: ECE;Bit 7: CWR;Bit 8: NS */
	uint32_t ip_version:4;	/* IP version */
	uint32_t frag:1;	/* Packet is an IP fragment */
	uint32_t svlan_tag:1;	/* The first vlan in the packet is s-vlan (0x8a88). cvlan_tag and ;svlan_tag cannot be set together */
	uint32_t cvlan_tag:1;	/* The first vlan in the packet is c-vlan (0x8100). cvlan_tag and ;svlan_tag cannot be set together */
	uint32_t ip_ecn:2;	/* Explicit Congestion Notification derived from Traffic Class/TOS ;field of IPv6/v4 */
	uint32_t ip_dscp:6;	/* Differentiated Services Code Point derived from Traffic Class/;TOS field of IPv6/v4 */
	uint32_t ip_protocol:8;	/* IP protocol */
	uint32_t tcp_dport:16;	/* TCP destination port. ;tcp and udp sport/dport are mutually exclusive */
	uint32_t tcp_sport:16;	/* TCP source port.;tcp and udp sport/dport are mutually exclusive */
	uint32_t ip_ttl_hoplimit:8;
	uint32_t reserved:24;
	uint32_t udp_dport:16;	/* UDP destination port.;tcp and udp sport/dport are mutually exclusive */
	uint32_t udp_sport:16;	/* UDP source port.;tcp and udp sport/dport are mutually exclusive */
	uint32_t src_ip_127_96;	/* IPv6 source address of incoming packets ;For IPv4 address use bits 31:0 (rest of the bits are reserved);This field should be qualified by an appropriate ;ethertype */
	uint32_t src_ip_95_64;	/* IPv6 source address of incoming packets ;For IPv4 address use bits 31:0 (rest of the bits are reserved);This field should be qualified by an appropriate ;ethertype */
	uint32_t src_ip_63_32;	/* IPv6 source address of incoming packets ;For IPv4 address use bits 31:0 (rest of the bits are reserved);This field should be qualified by an appropriate ;ethertype */
	uint32_t src_ip_31_0;	/* IPv6 source address of incoming packets ;For IPv4 address use bits 31:0 (rest of the bits are reserved);This field should be qualified by an appropriate ;ethertype */
	uint32_t dst_ip_127_96;	/* IPv6 destination address of incoming packets ;For IPv4 address use bits 31:0 (rest of the bits are reserved);This field should be qualified by an appropriate ;ethertype */
	uint32_t dst_ip_95_64;	/* IPv6 destination address of incoming packets ;For IPv4 address use bits 31:0 (rest of the bits are reserved);This field should be qualified by an appropriate ;ethertype */
	uint32_t dst_ip_63_32;	/* IPv6 destination address of incoming packets ;For IPv4 address use bits 31:0 (rest of the bits are reserved);This field should be qualified by an appropriate ;ethertype */
	uint32_t dst_ip_31_0;	/* IPv6 destination address of incoming packets ;For IPv4 address use bits 31:0 (rest of the bits are reserved);This field should be qualified by an appropriate ;ethertype */
};

struct dr_match_param {
	struct dr_match_spec	outer;
	/* There are more match param according to PRM but we are not
	 * going to use them in the test. see 'struct dr_match_param'
	 * in rdma-core code.
	 */
};

struct mlx5_ifc_dr_match_spec_bits {
	u8         smac_47_16[0x20];

	u8         smac_15_0[0x10];
	u8         ethertype[0x10];

	u8         dmac_47_16[0x20];

	u8         dmac_15_0[0x10];
	u8         first_prio[0x3];
	u8         first_cfi[0x1];
	u8         first_vid[0xc];

	u8         ip_protocol[0x8];
	u8         ip_dscp[0x6];
	u8         ip_ecn[0x2];
	u8         cvlan_tag[0x1];
	u8         svlan_tag[0x1];
	u8         frag[0x1];
	u8         ip_version[0x4];
	u8         tcp_flags[0x9];

	u8         tcp_sport[0x10];
	u8         tcp_dport[0x10];

	u8         reserved_at_c0[0x18];
	u8         ip_ttl_hoplimit[0x8];

	u8         udp_sport[0x10];
	u8         udp_dport[0x10];

	u8         src_ip_127_96[0x20];

	u8         src_ip_95_64[0x20];

	u8         src_ip_63_32[0x20];

	u8         src_ip_31_0[0x20];

	u8         dst_ip_127_96[0x20];

	u8         dst_ip_95_64[0x20];

	u8         dst_ip_63_32[0x20];

	u8         dst_ip_31_0[0x20];
};

#endif
