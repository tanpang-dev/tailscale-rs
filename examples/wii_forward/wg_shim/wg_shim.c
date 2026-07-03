// SPDX-License-Identifier: GPL-2.0
/*
 * wg_shim: supplies the kernel symbols that wireguard-linux-compat needs but
 * that this minimal Wii kernel (CONFIG_TRIM_UNUSED_KSYMS=y) does not export.
 *
 * Three kinds of symbols are provided:
 *
 *  1. Ports: functions whose code is absent from the kernel entirely
 *     (CONFIG_NET_UDP_TUNNEL off, siphash lib trimmed, ...). Copied verbatim
 *     from Linux v4.19.325 (GPL-2.0), lightly adapted to call only exported
 *     symbols or injected pointers.
 *
 *  2. Trampolines: functions whose code exists in the kernel .text but whose
 *     export entry was trimmed. The loader script looks up their address in
 *     /proc/kallsyms and passes it in as a module parameter; the shim exports
 *     a wrapper that jumps to the real implementation.
 *
 *  3. Stubs: IPv6-only paths. ipv6_mod_enabled() returns false, which makes
 *     wireguard skip creating a v6 UDP socket, so the v6 tunnel/dst-cache
 *     functions below are never reached at runtime; they only need to exist
 *     so the module loads. The tailnet runs IPv4 underlay only.
 */

/* CONFIG_TRIM_UNUSED_KSYMS makes EXPORT_SYMBOL() a no-op unless the symbol
 * is whitelisted in generated/autoksyms.h (__KSYM_<name>). This kernel's
 * whitelist obviously doesn't include symbols meant for out-of-tree
 * wireguard, so force every export through the filter. Must precede all
 * includes so linux/export.h sees these. */
#define __KSYM_sg_nents 1
#define __KSYM_sg_miter_start 1
#define __KSYM_sg_miter_next 1
#define __KSYM_sg_miter_stop 1
#define __KSYM___skb_get_hash 1
#define __KSYM_wait_for_random_bytes 1
#define __KSYM_call_rcu_bh 1
#define __KSYM_rcu_barrier_bh 1
#define __KSYM_ktime_get_coarse_with_offset 1
#define __KSYM_hsiphash_2u32 1
#define __KSYM_hsiphash_3u32 1
#define __KSYM_pskb_put 1
#define __KSYM_skb_to_sgvec 1
#define __KSYM_skb_cow_data 1
#define __KSYM_udp_sock_create4 1
#define __KSYM_setup_udp_tunnel_sock 1
#define __KSYM_udp_tunnel_xmit_skb 1
#define __KSYM_udp_tunnel_sock_release 1
#define __KSYM_ipv6_mod_enabled 1
#define __KSYM_udp_sock_create6 1
#define __KSYM_udp_tunnel6_xmit_skb 1
#define __KSYM_ipv6_chk_addr 1
#define __KSYM_dst_cache_get_ip6 1
#define __KSYM_dst_cache_set_ip6 1

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/timekeeping.h>
#include <linux/siphash.h>
#include <linux/scatterlist.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/ip_tunnels.h>
#include <net/dst_cache.h>
#include <net/addrconf.h>
#include <net/sock.h>

/* ------------------------------------------------------------------ */
/* Injected addresses of present-but-unexported kernel functions.      */
/* Resolved from /proc/kallsyms by the loader script.                  */
/* ------------------------------------------------------------------ */

static unsigned long p_udp_encap_enable;
static unsigned long p_sg_nents;
static unsigned long p_sg_miter_start;
static unsigned long p_sg_miter_next;
static unsigned long p_sg_miter_stop;
static unsigned long p_skb_get_hash;
static unsigned long p_wait_for_random_bytes;
static unsigned long p_call_rcu_bh;
static unsigned long p_rcu_barrier_bh;

module_param(p_udp_encap_enable, ulong, 0);
module_param(p_sg_nents, ulong, 0);
module_param(p_sg_miter_start, ulong, 0);
module_param(p_sg_miter_next, ulong, 0);
module_param(p_sg_miter_stop, ulong, 0);
module_param(p_skb_get_hash, ulong, 0);
module_param(p_wait_for_random_bytes, ulong, 0);
module_param(p_call_rcu_bh, ulong, 0);
module_param(p_rcu_barrier_bh, ulong, 0);

/* ------------------------------------------------------------------ */
/* 2. Trampolines                                                      */
/* ------------------------------------------------------------------ */

int sg_nents(struct scatterlist *sg)
{
	return ((int (*)(struct scatterlist *))p_sg_nents)(sg);
}
EXPORT_SYMBOL(sg_nents);

void sg_miter_start(struct sg_mapping_iter *miter, struct scatterlist *sgl,
		    unsigned int nents, unsigned int flags)
{
	((void (*)(struct sg_mapping_iter *, struct scatterlist *,
		   unsigned int, unsigned int))p_sg_miter_start)(miter, sgl,
								 nents, flags);
}
EXPORT_SYMBOL(sg_miter_start);

bool sg_miter_next(struct sg_mapping_iter *miter)
{
	return ((bool (*)(struct sg_mapping_iter *))p_sg_miter_next)(miter);
}
EXPORT_SYMBOL(sg_miter_next);

void sg_miter_stop(struct sg_mapping_iter *miter)
{
	((void (*)(struct sg_mapping_iter *))p_sg_miter_stop)(miter);
}
EXPORT_SYMBOL(sg_miter_stop);

void __skb_get_hash(struct sk_buff *skb)
{
	((void (*)(struct sk_buff *))p_skb_get_hash)(skb);
}
EXPORT_SYMBOL(__skb_get_hash);

int wait_for_random_bytes(void)
{
	if (p_wait_for_random_bytes)
		return ((int (*)(void))p_wait_for_random_bytes)();
	/* System has been up for ages by the time this module loads. */
	return 0;
}
EXPORT_SYMBOL(wait_for_random_bytes);

void call_rcu_bh(struct rcu_head *head, rcu_callback_t func)
{
	if (p_call_rcu_bh)
		((void (*)(struct rcu_head *, rcu_callback_t))p_call_rcu_bh)(head, func);
	else
		call_rcu(head, func); /* superset grace period; UP-safe */
}
EXPORT_SYMBOL(call_rcu_bh);

void rcu_barrier_bh(void)
{
	if (p_rcu_barrier_bh)
		((void (*)(void))p_rcu_barrier_bh)();
	else
		rcu_barrier();
}
EXPORT_SYMBOL(rcu_barrier_bh);

/* Exported ktime_get_with_offset() is the precise superset of the
 * trimmed coarse variant; correctness only improves. */
ktime_t ktime_get_coarse_with_offset(enum tk_offsets offs)
{
	return ktime_get_with_offset(offs);
}
EXPORT_SYMBOL(ktime_get_coarse_with_offset);

/* ------------------------------------------------------------------ */
/* 1a. Ports from lib/siphash.c (v4.19.325), 32-bit hsiphash variant.  */
/* ------------------------------------------------------------------ */

#ifndef HSIPHASH_PERMUTATION
#define HSIPHASH_PERMUTATION(a, b, c, d) ( \
	(a) += (b), (b) = rol32((b), 5), (b) ^= (a), (a) = rol32((a), 16), \
	(c) += (d), (d) = rol32((d), 8), (d) ^= (c), \
	(a) += (d), (d) = rol32((d), 7), (d) ^= (a), \
	(c) += (b), (b) = rol32((b), 13), (b) ^= (c), (c) = rol32((c), 16))
#define HSIPHASH_CONST_0 0U
#define HSIPHASH_CONST_1 0U
#define HSIPHASH_CONST_2 0x6c796765U
#define HSIPHASH_CONST_3 0x74656462U
#endif

#if BITS_PER_LONG != 32
#error "this hsiphash port is the 32-bit variant; Wii is ppc32"
#endif

#define HSIPROUND HSIPHASH_PERMUTATION(v0, v1, v2, v3)

#define HPREAMBLE(len) \
	u32 v0 = HSIPHASH_CONST_0; \
	u32 v1 = HSIPHASH_CONST_1; \
	u32 v2 = HSIPHASH_CONST_2; \
	u32 v3 = HSIPHASH_CONST_3; \
	u32 b = ((u32)(len)) << 24; \
	v3 ^= key->key[1]; \
	v2 ^= key->key[0]; \
	v1 ^= key->key[1]; \
	v0 ^= key->key[0];

#define HPOSTAMBLE \
	v3 ^= b; \
	HSIPROUND; \
	v0 ^= b; \
	v2 ^= 0xff; \
	HSIPROUND; \
	HSIPROUND; \
	HSIPROUND; \
	return v1 ^ v3;

u32 hsiphash_2u32(const u32 first, const u32 second, const hsiphash_key_t *key)
{
	HPREAMBLE(8)
	v3 ^= first;
	HSIPROUND;
	v0 ^= first;
	v3 ^= second;
	HSIPROUND;
	v0 ^= second;
	HPOSTAMBLE
}
EXPORT_SYMBOL(hsiphash_2u32);

u32 hsiphash_3u32(const u32 first, const u32 second, const u32 third,
		  const hsiphash_key_t *key)
{
	HPREAMBLE(12)
	v3 ^= first;
	HSIPROUND;
	v0 ^= first;
	v3 ^= second;
	HSIPROUND;
	v0 ^= second;
	v3 ^= third;
	HSIPROUND;
	v0 ^= third;
	HPOSTAMBLE
}
EXPORT_SYMBOL(hsiphash_3u32);

/* ------------------------------------------------------------------ */
/* 1b. Ports from net/core/skbuff.c (v4.19.325).                       */
/* All callees are exported: skb_put, __pskb_pull_tail,                */
/* pskb_expand_head, skb_copy, skb_copy_expand, skb_set_owner_w,       */
/* kfree_skb.                                                          */
/* ------------------------------------------------------------------ */

void *pskb_put(struct sk_buff *skb, struct sk_buff *tail, int len)
{
	if (tail != skb) {
		skb->data_len += len;
		skb->len += len;
	}
	return skb_put(tail, len);
}
EXPORT_SYMBOL(pskb_put);

static int shim__skb_to_sgvec(struct sk_buff *skb, struct scatterlist *sg,
			      int offset, int len,
			      unsigned int recursion_level)
{
	int start = skb_headlen(skb);
	int i, copy = start - offset;
	struct sk_buff *frag_iter;
	int elt = 0;

	if (unlikely(recursion_level >= 24))
		return -EMSGSIZE;

	if (copy > 0) {
		if (copy > len)
			copy = len;
		sg_set_buf(sg, skb->data + offset, copy);
		elt++;
		if ((len -= copy) == 0)
			return elt;
		offset += copy;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		int end;

		WARN_ON(start > offset + len);

		end = start + skb_frag_size(&skb_shinfo(skb)->frags[i]);
		if ((copy = end - offset) > 0) {
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

			if (unlikely(elt && sg_is_last(&sg[elt - 1])))
				return -EMSGSIZE;

			if (copy > len)
				copy = len;
			sg_set_page(&sg[elt], skb_frag_page(frag), copy,
				    frag->page_offset + offset - start);
			elt++;
			if (!(len -= copy))
				return elt;
			offset += copy;
		}
		start = end;
	}

	skb_walk_frags(skb, frag_iter) {
		int end, ret;

		WARN_ON(start > offset + len);

		end = start + frag_iter->len;
		if ((copy = end - offset) > 0) {
			if (unlikely(elt && sg_is_last(&sg[elt - 1])))
				return -EMSGSIZE;

			if (copy > len)
				copy = len;
			ret = shim__skb_to_sgvec(frag_iter, sg + elt,
						 offset - start, copy,
						 recursion_level + 1);
			if (unlikely(ret < 0))
				return ret;
			elt += ret;
			if ((len -= copy) == 0)
				return elt;
			offset += copy;
		}
		start = end;
	}
	BUG_ON(len);
	return elt;
}

int skb_to_sgvec(struct sk_buff *skb, struct scatterlist *sg, int offset,
		 int len)
{
	int nsg = shim__skb_to_sgvec(skb, sg, offset, len, 0);

	if (nsg <= 0)
		return nsg;

	sg_mark_end(&sg[nsg - 1]);

	return nsg;
}
EXPORT_SYMBOL(skb_to_sgvec);

int skb_cow_data(struct sk_buff *skb, int tailbits, struct sk_buff **trailer)
{
	int copyflag;
	int elt;
	struct sk_buff *skb1, **skb_p;

	if ((skb_cloned(skb) || skb_shinfo(skb)->nr_frags) &&
	    __pskb_pull_tail(skb, skb_pagelen(skb) - skb_headlen(skb)) == NULL)
		return -ENOMEM;

	if (!skb_has_frag_list(skb)) {
		if (skb_tailroom(skb) < tailbits &&
		    pskb_expand_head(skb, 0,
				     tailbits - skb_tailroom(skb) + 128,
				     GFP_ATOMIC))
			return -ENOMEM;

		*trailer = skb;
		return 1;
	}

	elt = 1;
	skb_p = &skb_shinfo(skb)->frag_list;
	copyflag = 0;

	while ((skb1 = *skb_p) != NULL) {
		int ntail = 0;

		if (skb_shared(skb1))
			copyflag = 1;

		if (skb1->next == NULL && tailbits) {
			if (skb_shinfo(skb1)->nr_frags ||
			    skb_has_frag_list(skb1) ||
			    skb_tailroom(skb1) < tailbits)
				ntail = tailbits + 128;
		}

		if (copyflag ||
		    skb_cloned(skb1) ||
		    ntail ||
		    skb_shinfo(skb1)->nr_frags ||
		    skb_has_frag_list(skb1)) {
			struct sk_buff *skb2;

			if (ntail == 0)
				skb2 = skb_copy(skb1, GFP_ATOMIC);
			else
				skb2 = skb_copy_expand(skb1,
						       skb_headroom(skb1),
						       ntail,
						       GFP_ATOMIC);
			if (unlikely(skb2 == NULL))
				return -ENOMEM;

			if (skb1->sk)
				skb_set_owner_w(skb2, skb1->sk);

			skb2->next = skb1->next;
			*skb_p = skb2;
			kfree_skb(skb1);
			skb1 = skb2;
		}
		elt++;
		*trailer = skb1;
		skb_p = &skb1->next;
	}

	return elt;
}
EXPORT_SYMBOL(skb_cow_data);

/* ------------------------------------------------------------------ */
/* 1c. Ports from net/ipv4/udp_tunnel.c (v4.19.325).                   */
/* ------------------------------------------------------------------ */

int udp_sock_create4(struct net *net, struct udp_port_cfg *cfg,
		     struct socket **sockp)
{
	int err;
	struct socket *sock = NULL;
	struct sockaddr_in udp_addr;

	err = sock_create_kern(net, AF_INET, SOCK_DGRAM, 0, &sock);
	if (err < 0)
		goto error;

	udp_addr.sin_family = AF_INET;
	udp_addr.sin_addr = cfg->local_ip;
	udp_addr.sin_port = cfg->local_udp_port;
	err = kernel_bind(sock, (struct sockaddr *)&udp_addr,
			  sizeof(udp_addr));
	if (err < 0)
		goto error;

	if (cfg->peer_udp_port) {
		udp_addr.sin_family = AF_INET;
		udp_addr.sin_addr = cfg->peer_ip;
		udp_addr.sin_port = cfg->peer_udp_port;
		err = kernel_connect(sock, (struct sockaddr *)&udp_addr,
				     sizeof(udp_addr), 0);
		if (err < 0)
			goto error;
	}

	sock->sk->sk_no_check_tx = !cfg->use_udp_checksums;

	*sockp = sock;
	return 0;

error:
	if (sock) {
		kernel_sock_shutdown(sock, SHUT_RDWR);
		sock_release(sock);
	}
	*sockp = NULL;
	return err;
}
EXPORT_SYMBOL(udp_sock_create4);

void setup_udp_tunnel_sock(struct net *net, struct socket *sock,
			   struct udp_tunnel_sock_cfg *cfg)
{
	struct sock *sk = sock->sk;

	/* Disable multicast loopback */
	inet_sk(sk)->mc_loop = 0;

	/* Enable CHECKSUM_UNNECESSARY to CHECKSUM_COMPLETE conversion */
	inet_inc_convert_csum(sk);

	rcu_assign_sk_user_data(sk, cfg->sk_user_data);

	udp_sk(sk)->encap_type = cfg->encap_type;
	udp_sk(sk)->encap_rcv = cfg->encap_rcv;
	udp_sk(sk)->encap_destroy = cfg->encap_destroy;
	udp_sk(sk)->gro_receive = cfg->gro_receive;
	udp_sk(sk)->gro_complete = cfg->gro_complete;

	/* Upstream calls udp_tunnel_encap_enable(); inlined here so the
	 * v4 branch goes through the injected udp_encap_enable pointer and
	 * the v6 branch (unreachable: ipv6_mod_enabled() is false) traps. */
	if (WARN_ON(sk->sk_family == PF_INET6))
		return;
	((void (*)(void))p_udp_encap_enable)();
}
EXPORT_SYMBOL(setup_udp_tunnel_sock);

/* Static copy of udp_set_csum() (net/ipv4/udp.c); uses only inlines. */
static void shim_udp_set_csum(bool nocheck, struct sk_buff *skb,
			      __be32 saddr, __be32 daddr, int len)
{
	struct udphdr *uh = udp_hdr(skb);

	if (nocheck) {
		uh->check = 0;
	} else if (skb_is_gso(skb)) {
		uh->check = ~udp_v4_check(len, saddr, daddr, 0);
	} else if (skb->ip_summed == CHECKSUM_PARTIAL) {
		uh->check = 0;
		uh->check = udp_v4_check(len, saddr, daddr, lco_csum(skb));
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;
	} else {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
		uh->check = ~udp_v4_check(len, saddr, daddr, 0);
	}
}

void udp_tunnel_xmit_skb(struct rtable *rt, struct sock *sk,
			 struct sk_buff *skb, __be32 src, __be32 dst,
			 __u8 tos, __u8 ttl, __be16 df, __be16 src_port,
			 __be16 dst_port, bool xnet, bool nocheck)
{
	struct udphdr *uh;

	__skb_push(skb, sizeof(*uh));
	skb_reset_transport_header(skb);
	uh = udp_hdr(skb);

	uh->dest = dst_port;
	uh->source = src_port;
	uh->len = htons(skb->len);

	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));

	shim_udp_set_csum(nocheck, skb, src, dst, skb->len);

	iptunnel_xmit(sk, rt, skb, src, dst, IPPROTO_UDP, tos, ttl, df, xnet);
}
EXPORT_SYMBOL(udp_tunnel_xmit_skb);

void udp_tunnel_sock_release(struct socket *sock)
{
	rcu_assign_sk_user_data(sock->sk, NULL);
	synchronize_rcu();
	kernel_sock_shutdown(sock, SHUT_RDWR);
	sock_release(sock);
}
EXPORT_SYMBOL(udp_tunnel_sock_release);

/* ------------------------------------------------------------------ */
/* 3. IPv6 stubs. ipv6_mod_enabled() returning false makes wireguard   */
/* run IPv4-underlay-only, so none of these are reached at runtime.    */
/* ------------------------------------------------------------------ */

bool ipv6_mod_enabled(void)
{
	return false;
}
EXPORT_SYMBOL(ipv6_mod_enabled);

int udp_sock_create6(struct net *net, struct udp_port_cfg *cfg,
		     struct socket **sockp)
{
	*sockp = NULL;
	return -EAFNOSUPPORT;
}
EXPORT_SYMBOL(udp_sock_create6);

int udp_tunnel6_xmit_skb(struct dst_entry *dst, struct sock *sk,
			 struct sk_buff *skb, struct net_device *dev,
			 struct in6_addr *saddr, struct in6_addr *daddr,
			 __u8 prio, __u8 ttl, __be32 label, __be16 src_port,
			 __be16 dst_port, bool nocheck)
{
	WARN_ON_ONCE(1);
	kfree_skb(skb);
	return -EAFNOSUPPORT;
}
EXPORT_SYMBOL(udp_tunnel6_xmit_skb);

int ipv6_chk_addr(struct net *net, const struct in6_addr *addr,
		  const struct net_device *dev, int strict)
{
	return 0;
}
EXPORT_SYMBOL(ipv6_chk_addr);

struct dst_entry *dst_cache_get_ip6(struct dst_cache *dst_cache,
				    struct in6_addr *saddr)
{
	return NULL;
}
EXPORT_SYMBOL(dst_cache_get_ip6);

void dst_cache_set_ip6(struct dst_cache *dst_cache, struct dst_entry *dst,
		       const struct in6_addr *addr)
{
	/* Upstream takes its own reference on dst; the caller keeps its own,
	 * so "don't cache" is simply a no-op. */
}
EXPORT_SYMBOL(dst_cache_set_ip6);

/* ------------------------------------------------------------------ */

static int __init wg_shim_init(void)
{
	if (!p_udp_encap_enable || !p_sg_nents || !p_sg_miter_start ||
	    !p_sg_miter_next || !p_sg_miter_stop || !p_skb_get_hash) {
		pr_err("wg_shim: missing required kallsyms addresses\n");
		return -EINVAL;
	}
	pr_info("wg_shim: loaded (IPv4 underlay only)\n");
	return 0;
}

static void __exit wg_shim_exit(void)
{
	/* Exported call_rcu_bh callbacks may still be queued; make sure all
	 * grace periods have elapsed before our text goes away. */
	rcu_barrier();
	if (p_rcu_barrier_bh)
		((void (*)(void))p_rcu_barrier_bh)();
}

module_init(wg_shim_init);
module_exit(wg_shim_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Trimmed-ksyms shim for wireguard-linux-compat on the Wii");
