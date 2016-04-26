#ifndef _LINUX_MPLS_H_
#define _LINUX_MPLS_H_

#define PLATFORM_LABELS_MAX 1000

struct mpls_label
{
	uint32_t entry;
};

struct rta_via_attr
{
	uint16_t family;
	uint32_t addr;
} __attribute__ ((packed));

#define MPLS_LS_LABEL_MASK		0xFFFFF000
#define MPLS_LS_LABEL_SHIFT		12
#define MPLS_LS_TC_MASK			0x00000E00
#define MPLS_LS_TC_SHIFT		9
#define MPLS_LS_S_MASK			0x00000100
#define MPLS_LS_S_SHIFT			8
#define MPLS_LS_TTL_MASK		0x000000FF
#define MPLS_LS_TTL_SHIFT		0

#endif
