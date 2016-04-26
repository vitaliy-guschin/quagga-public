#include <zebra.h>
#include <linux/mpls_linux.h>
#include "zebra/mpls_lib.h"
#include "zebra/rt_netlink.h"
#include "zebra/debug.h"
#include "if.h"
#include "privs.h"
#include "log.h"

#define NETLINK_BUFF_SIZE 1024

extern struct zebra_privs_t zserv_privs;

extern const struct message nlmsg_str[];

static struct nlsock netlink_mpls = 
        { -1, 0, {0}, "netlink-mpls"};


static int build_mpls_label(
		struct mpls_label * label,
		uint32_t value)
{
	/* Fail when the label value is out or range */
	if (value >= (1 << 20))
		return -1;

	/* Label */
	label->entry = htonl(value << MPLS_LS_LABEL_SHIFT);

	/* S */
	label->entry |= htonl(1 << MPLS_LS_S_SHIFT);

	return 0;
}

static int mpls_interface_set_input(
		char * iface,
		int input)
{
	if (NULL == iface)
	{
		return -1;
	}

	int ret = 0;
	char path[256];
	memset(path, 0, sizeof(path));

	snprintf(path, sizeof(path), "/proc/sys/net/mpls/conf/%s/input", iface);

	FILE * fp = fopen(path, "w");
	if (NULL == fp)
	{
		return -1;
	}

	ret = fprintf(fp, "%d\n", input);
	if (ret <= 0)
	{
		fclose (fp);
		return -1;
	}

	fclose (fp);

	return 0;
}

static int mpls_kernel_ilm(
		int cmd,
		int flags,
		u_int32_t in_label,
		struct mpls_lsp * lsp)
{
	if (IS_ZEBRA_DEBUG_KERNEL)
	{
		zlog_debug ("<%s>: type=%s, in label=%u",
		        __func__, lookup(nlmsg_str, cmd), in_label);
	}

	struct mpls_label label;
	struct rta_via_attr via;

	struct
	{
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[NETLINK_BUFF_SIZE];
	} req;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | flags;
	req.n.nlmsg_type = cmd;
	req.r.rtm_family = AF_MPLS;
	req.r.rtm_dst_len = 20;
	req.r.rtm_table = RT_TABLE_MAIN;
	req.r.rtm_protocol = RTPROT_ZEBRA;
	req.r.rtm_scope = RT_SCOPE_UNIVERSE;
	req.r.rtm_type = RTN_UNICAST;

	/* Input label */
	memset(&label, 0, sizeof(struct mpls_label));

	if (0 != build_mpls_label(&label, in_label))
	{
		if (IS_ZEBRA_DEBUG_KERNEL)
		{
			zlog_debug ("<%s>: Ivalid input label", __func__);
		}

		return -1;
	}

	addattr_l(&req.n, sizeof(req), RTA_DST, &label, sizeof(label));

	/* Output label */
	if (lsp->remote_label != MPLS_IMPLICIT_NULL)
	{
		memset(&label, 0, sizeof(label));

		if (0 != build_mpls_label(&label, lsp->remote_label))
		{
			if (IS_ZEBRA_DEBUG_KERNEL)
			{
				zlog_debug ("<%s>: Invalid output label", __func__);
			}
		}

		addattr_l(&req.n, sizeof(req), RTA_NEWDST, &label, sizeof(label));
	}

	/* Output interface */
	addattr32(&req.n, sizeof(req), RTA_OIF, lsp->ifp->ifindex);

	/* Nexthop */
	memset(&via, 0, sizeof(via));
	via.family = AF_INET;
	via.addr = lsp->addr.s_addr;
	addattr_l(&req.n, sizeof(req), RTA_VIA, &via, 6);

	return netlink_talk(&req.n, &netlink_mpls);
}

static int mpls_platform_labels_set_count(
		int count)
{
	if (count >= (1 << 20))
	{
		return -1;
	}

	int ret = 0;

	FILE * fp = fopen("/proc/sys/net/mpls/platform_labels", "w");
	if (NULL == fp)
	{
		return -1;
	}

	ret = fprintf(fp, "%d\n", count);
	if (ret <= 0)
	{
		fclose (fp);
		return -1;
	}

	fclose (fp);
	return 0;
}

int mpls_kernel_enable_interface(
		struct interface *ifp)
{
	int ret = 0;

	if (zserv_privs.change(ZPRIVS_RAISE))
	{
		zlog_err("Can't raise privileges\n");
		return -1;
	}

	ret =  mpls_interface_set_input(ifp->name, 1);

	if (0 != ret)
	{
		zlog_err("Can't enable MPLS on interface '%s'\n", ifp->name);
		goto out;
	}

out:
	if (zserv_privs.change(ZPRIVS_LOWER))
		zlog_err("Can't lower privileges\n");

	return ret;
}

int mpls_kernel_disable_interface(
		struct interface *ifp)
{
	int ret = 0;

	if (zserv_privs.change(ZPRIVS_RAISE))
	{
		zlog_err("Can't raise privileges\n");
		return -1;
	}

	ret = mpls_interface_set_input(ifp->name, 0);

	if (0 != ret)
	{
		zlog_err("Can't disable MPLS on interface '%s'\n", ifp->name);
		goto out;
	}

out:
	if (zserv_privs.change(ZPRIVS_LOWER))
	{
		zlog_err("Can't lower privileges\n");
	}

	return ret;
}

int mpls_kernel_install_ilm(
		u_int32_t in_label,
		struct mpls_lsp *lsp)
{
	if (NULL == lsp)
		return 0;

	return mpls_kernel_ilm(
	        RTM_NEWROUTE,
	        NLM_F_CREATE | NLM_F_REPLACE,
	        in_label,
	        lsp);
}

int mpls_kernel_uninstall_ilm(
		u_int32_t in_label,
		struct mpls_lsp *lsp)
{
	if (NULL == lsp)
		return 0;

	return mpls_kernel_ilm(
	        RTM_DELROUTE,
	        0,
	        in_label,
	        lsp);
}

void mpls_kernel_init(void)
{
	netlink_socket(&netlink_mpls, 0);

	if (zserv_privs.change(ZPRIVS_RAISE))
	{
		zlog_err("Can't raise privileges\n");
		return;
	}

	/* Set mpls table size */
	if (0 != mpls_platform_labels_set_count(PLATFORM_LABELS_MAX))
	{
		if (IS_ZEBRA_DEBUG_KERNEL)
		{
			zlog_debug ("<%s>: Cat not set MPLS table size (%d)",
			        __func__, PLATFORM_LABELS_MAX);
		}
	}

	if (zserv_privs.change(ZPRIVS_LOWER))
	{
		zlog_err("Can't lower privileges\n");
	}
}

void mpls_kernel_exit(void)
{
	/* Close Netlink socket */
	close(netlink_mpls.sock);
}
