#include <zebra.h>
#include "zebra/mpls_lib.h"
#include "if.h"
#include "privs.h"
#include "log.h"

extern struct zebra_privs_t zserv_privs;

static int mpls_interface_set_input(char * iface, int input)
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
		zlog_err("Can't lower privileges\n");

	return ret;
}

int mpls_kernel_install_ilm(
		u_int32_t in_label,
		struct mpls_lsp *lsp)
{
	return 0;
}

int mpls_kernel_uninstall_ilm(
		u_int32_t in_label,
		struct mpls_lsp *lsp)
{
	return 0;
}

void mpls_kernel_init(void)
{
}

void mpls_kernel_exit(void)
{
}
