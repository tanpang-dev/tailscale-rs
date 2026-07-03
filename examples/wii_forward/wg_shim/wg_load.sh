#!/bin/sh
# Load wg_shim (with kallsyms-injected addresses) then wireguard.
set -e

grep -qw wireguard /proc/modules && { echo "wireguard already loaded"; exit 0; }

echo 0 > /proc/sys/kernel/kptr_restrict

addr() {
	awk -v s="$1" '$3 == s { print "0x" $1; exit }' /proc/kallsyms
}

req() {
	a=$(addr "$1")
	[ -n "$a" ] || { echo "missing kallsyms entry: $1" >&2; exit 1; }
	echo "$a"
}

if ! grep -qw wg_shim /proc/modules; then
	insmod /root/wg_shim/wg_shim.ko \
		p_udp_encap_enable="$(req udp_encap_enable)" \
		p_sg_nents="$(req sg_nents)" \
		p_sg_miter_start="$(req sg_miter_start)" \
		p_sg_miter_next="$(req sg_miter_next)" \
		p_sg_miter_stop="$(req sg_miter_stop)" \
		p_skb_get_hash="$(req __skb_get_hash)" \
		p_wait_for_random_bytes="$(addr wait_for_random_bytes)" \
		p_call_rcu_bh="$(addr call_rcu_bh)" \
		p_rcu_barrier_bh="$(addr rcu_barrier_bh)"
fi

insmod /root/wireguard-linux-compat/src/wireguard.ko
echo "wireguard loaded:"
grep -w wireguard /proc/modules
