/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2015, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
#define DEBUG_SUBSYSTEM S_LNET

#include <linux/if.h>
#include <linux/in.h>
#include <linux/net.h>
#include <net/addrconf.h>
#include <net/ipv6.h>
#include <linux/file.h>
#include <linux/pagemap.h>
/* For sys_open & sys_close */
#include <linux/syscalls.h>
#include <net/sock.h>
#include <linux/inetdevice.h>

#include <libcfs/libcfs.h>
#include <lnet/lib-lnet.h>

/*
 * kernel 5.1: commit 7f1bc6e95d7840d4305595b3e4025cddda88cee5
 * Y2038 64-bit time.
 *  SO_TIMESTAMP, SO_TIMESTAMPNS and SO_TIMESTAMPING options, the
 *  way they are currently defined, are not y2038 safe.
 *  Subsequent patches in the series add new y2038 safe versions
 *  of these options which provide 64 bit timestamps on all
 *  architectures uniformly.
 *  Hence, rename existing options with OLD tag suffixes.
 *
 * NOTE: When updating to timespec64 change change these to '_NEW'.
 *
 */
#ifndef SO_SNDTIMEO
#define SO_SNDTIMEO SO_SNDTIMEO_OLD
#endif

#ifndef SO_RCVTIMEO
#define SO_RCVTIMEO SO_RCVTIMEO_OLD
#endif

int
lnet_sock_write(struct socket *sock, void *buffer, int nob, int timeout)
{
	int		rc;
	long		jiffies_left = cfs_time_seconds(timeout);
	unsigned long	then;
	struct timeval	tv;

	LASSERT(nob > 0);
	/* Caller may pass a zero timeout if she thinks the socket buffer is
	 * empty enough to take the whole message immediately */

	for (;;) {
		struct kvec  iov = {
			.iov_base = buffer,
			.iov_len  = nob
		};
		struct msghdr msg = {
			.msg_flags	= (timeout == 0) ? MSG_DONTWAIT : 0
		};

		if (timeout != 0) {
			/* Set send timeout to remaining time */
			jiffies_to_timeval(jiffies_left, &tv);
			rc = kernel_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
					       (char *)&tv, sizeof(tv));
			if (rc != 0) {
				CERROR("Can't set socket send timeout "
				       "%ld.%06d: %d\n",
				       (long)tv.tv_sec, (int)tv.tv_usec, rc);
				return rc;
			}
		}

		then = jiffies;
		rc = kernel_sendmsg(sock, &msg, &iov, 1, nob);
		jiffies_left -= jiffies - then;

		if (rc == nob)
			return 0;

		if (rc < 0)
			return rc;

		if (rc == 0) {
			CERROR("Unexpected zero rc\n");
			return -ECONNABORTED;
		}

		if (jiffies_left <= 0)
			return -EAGAIN;

		buffer = ((char *)buffer) + rc;
		nob -= rc;
	}
	return 0;
}
EXPORT_SYMBOL(lnet_sock_write);

int
lnet_sock_read(struct socket *sock, void *buffer, int nob, int timeout)
{
	int		rc;
	long		jiffies_left = cfs_time_seconds(timeout);
	unsigned long	then;
	struct timeval	tv;

	LASSERT(nob > 0);
	LASSERT(jiffies_left > 0);

	for (;;) {
		struct kvec  iov = {
			.iov_base = buffer,
			.iov_len  = nob
		};
		struct msghdr msg = {
			.msg_flags	= 0
		};

		/* Set receive timeout to remaining time */
		jiffies_to_timeval(jiffies_left, &tv);
		rc = kernel_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
				       (char *)&tv, sizeof(tv));
		if (rc != 0) {
			CERROR("Can't set socket recv timeout %ld.%06d: %d\n",
			       (long)tv.tv_sec, (int)tv.tv_usec, rc);
			return rc;
		}

		then = jiffies;
		rc = kernel_recvmsg(sock, &msg, &iov, 1, nob, 0);
		jiffies_left -= jiffies - then;

		if (rc < 0)
			return rc;

		if (rc == 0)
			return -ECONNRESET;

		buffer = ((char *)buffer) + rc;
		nob -= rc;

		if (nob == 0)
			return 0;

		if (jiffies_left <= 0)
			return -ETIMEDOUT;
	}
}
EXPORT_SYMBOL(lnet_sock_read);

__u32 choose_ipv4_src(int interface, __u32 dst_ipaddr, struct net *ns)
{
	struct net_device *dev;
	struct in_device *in_dev;
	int err;
	__u32 ret = 0;
	DECLARE_CONST_IN_IFADDR(ifa);

	rtnl_lock();
	dev = dev_get_by_index(ns, interface);
	err = -EINVAL;
	if (!(dev->flags & IFF_UP))
		goto out;
	in_dev = __in_dev_get_rtnl(dev);
	if (!in_dev)
		goto out;
	in_dev_for_each_ifa_rtnl(ifa, in_dev) {
		if (ret == 0 ||
		    ((dst_ipaddr ^ ntohl(ifa->ifa_local))
		     & ntohl(ifa->ifa_mask)) == 0)
			/* This address at least as good as what we
			 * already have
			 */
			ret = ntohl(ifa->ifa_local);
	}
	endfor_ifa(in_dev);

	err = 0;
out:
	return err;
}

static struct socket *
lnet_sock_create(int interface, struct sockaddr *remaddr,
		 int local_port, struct net *ns)
{
	struct socket *sock;
	int rc;
	int option;
	int family;

	family = AF_INET6;
	if (remaddr)
		family = remaddr->sa_family;
#ifdef HAVE_SOCK_CREATE_KERN_USE_NET
	rc = sock_create_kern(ns, family, SOCK_STREAM, 0, &sock);
#else
	rc = sock_create_kern(family, SOCK_STREAM, 0, &sock);
#endif
	if (rc) {
		CERROR("Can't create socket: %d\n", rc);
		return ERR_PTR(rc);
	}

	option = 1;
	rc = kernel_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
			       (char *)&option, sizeof(option));
	if (rc) {
		CERROR("Can't set SO_REUSEADDR for socket: %d\n", rc);
		goto failed;
	}

	if (interface >= 0 || local_port != 0) {
		struct sockaddr_storage locaddr = {};
		struct sockaddr_in *sin = (void *)&locaddr;
		struct sockaddr_in6 *sin6 = (void *)&locaddr;

		switch (family) {
		case AF_INET:
			sin->sin_family = AF_INET;
			sin->sin_addr.s_addr = INADDR_ANY;
			if (interface >= 0 && remaddr) {
				struct sockaddr_in *rem = (void *)remaddr;

				sin->sin_addr.s_addr =
					choose_ipv4_src(
						interface,
						ntohl(rem->sin_addr.s_addr),
						ns);
			}
			sin->sin_port = htons(local_port);
			break;
		case AF_INET6:
			sin6->sin6_family = AF_INET6;
			sin6->sin6_addr = in6addr_any;
			if (interface >= 0 && remaddr) {
				struct sockaddr_in6 *rem = (void *)remaddr;

				ipv6_dev_get_saddr(ns,
						   dev_get_by_index(ns,
								    interface),
						   &rem->sin6_addr, 0,
						   &sin6->sin6_addr);
			}
			sin->sin_port = htons(local_port);
			break;
		}
		rc = kernel_bind(sock, (struct sockaddr *)&locaddr,
				 sizeof(locaddr));
		if (rc == -EADDRINUSE) {
			CDEBUG(D_NET, "Port %d already in use\n", local_port);
			goto failed;
		}
		if (rc != 0) {
			CERROR("Error trying to bind to port %d: %d\n",
			       local_port, rc);
			goto failed;
		}
	}
	return sock;

failed:
	sock_release(sock);
	return ERR_PTR(rc);
}

int
lnet_sock_setbuf(struct socket *sock, int txbufsize, int rxbufsize)
{
	int		    option;
	int		    rc;

	if (txbufsize != 0) {
		option = txbufsize;
		rc = kernel_setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
				       (char *)&option, sizeof(option));
		if (rc != 0) {
			CERROR("Can't set send buffer %d: %d\n",
				option, rc);
			return rc;
		}
	}

	if (rxbufsize != 0) {
		option = rxbufsize;
		rc = kernel_setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
				       (char *)&option, sizeof(option));
		if (rc != 0) {
			CERROR("Can't set receive buffer %d: %d\n",
				option, rc);
			return rc;
		}
	}
	return 0;
}
EXPORT_SYMBOL(lnet_sock_setbuf);

int
lnet_sock_getaddr(struct socket *sock, bool remote,
		  struct sockaddr_storage *peer)
{
	int rc;
#ifndef HAVE_KERN_SOCK_GETNAME_2ARGS
	int len = sizeof(peer);
#endif

	if (remote)
		rc = lnet_kernel_getpeername(sock,
					     (struct sockaddr *)peer, &len);
	else
		rc = lnet_kernel_getsockname(sock,
					     (struct sockaddr *)peer, &len);
	if (rc < 0) {
		CERROR("Error %d getting sock %s IP/port\n",
			rc, remote ? "peer" : "local");
		return rc;
	}
	if (peer->ss_family == AF_INET6) {
		struct sockaddr_in6 *in6 = (void *)peer;
		struct sockaddr_in *in = (void *)peer;
		short port = in6->sin6_port;

		if (ipv6_addr_v4mapped(&in6->sin6_addr)) {
			/* Pretend it is a v4 socket */
			memset(in, 0, sizeof(*in));
			in->sin_family = AF_INET;
			in->sin_port = port;
			memcpy(&in->sin_addr, &in6->sin6_addr.s6_addr32[3], 4);
		}
	}
	return 0;
}
EXPORT_SYMBOL(lnet_sock_getaddr);

int
lnet_sock_getbuf(struct socket *sock, int *txbufsize, int *rxbufsize)
{
	if (txbufsize != NULL)
		*txbufsize = sock->sk->sk_sndbuf;

	if (rxbufsize != NULL)
		*rxbufsize = sock->sk->sk_rcvbuf;

	return 0;
}
EXPORT_SYMBOL(lnet_sock_getbuf);

struct socket *
lnet_sock_listen(int local_port, int backlog, struct net *ns)
{
	struct socket *sock;
	int val = 0;
	int rc;

	sock = lnet_sock_create(-1, NULL, local_port, ns);
	if (IS_ERR(sock)) {
		rc = PTR_ERR(sock);
		if (rc == -EADDRINUSE)
			CERROR("Can't create socket: port %d already in use\n",
			       local_port);
		return ERR_PTR(rc);
	}

	/* Make sure we get both IPv4 and IPv6 connections.
	 * This is the default, but it can be overridden so
	 * we force it back.
	 */
	kernel_setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,
			  (char *) &val, sizeof(val));

	rc = kernel_listen(sock, backlog);
	if (rc == 0)
		return sock;

	CERROR("Can't set listen backlog %d: %d\n", backlog, rc);
	sock_release(sock);
	return ERR_PTR(rc);
}

struct socket *
lnet_sock_connect(int interface, int local_port,
		  struct sockaddr *peeraddr,
		  struct net *ns)
{
	struct socket *sock;
	int rc;

	sock = lnet_sock_create(interface, peeraddr, local_port, ns);
	if (IS_ERR(sock))
		return sock;

	rc = kernel_connect(sock, peeraddr, sizeof(struct sockaddr_in6), 0);
	if (rc == 0)
		return sock;

	/* EADDRNOTAVAIL probably means we're already connected to the same
	 * peer/port on the same local port on a differently typed
	 * connection.	Let our caller retry with a different local
	 * port... */

	CDEBUG_LIMIT(rc == -EADDRNOTAVAIL ? D_NET : D_NETERROR,
		     "Error %d connecting %d -> %pISp\n", rc,
		     local_port, peeraddr);

	sock_release(sock);
	return ERR_PTR(rc);
}
