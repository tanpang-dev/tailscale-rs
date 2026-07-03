# wg_shim — kernel WireGuard on the Wii's minimal kernel

The Wii's ArchPOWER kernel (`4.19.325-cip131-st15-wii+`) is built with
`CONFIG_TRIM_UNUSED_KSYMS=y`, so it exports only the symbols its own in-tree
modules use. `wireguard-linux-compat` (built against the on-device
`/lib/modules/$(uname -r)/build` tree) therefore fails to load with 24
unresolved symbols, even though the vermagic matches.

`wg_shim.ko` supplies those 24 symbols:

| kind | symbols |
|---|---|
| ports from v4.19.325 (GPL-2.0) | `hsiphash_2u32/3u32`, `pskb_put`, `skb_to_sgvec`, `skb_cow_data`, `udp_sock_create4`, `setup_udp_tunnel_sock`, `udp_tunnel_xmit_skb`, `udp_tunnel_sock_release` |
| trampolines (kallsyms address injected as module param) | `udp_encap_enable`, `sg_nents`, `sg_miter_start/next/stop`, `__skb_get_hash`, `wait_for_random_bytes`, `call_rcu_bh`, `rcu_barrier_bh` |
| unreachable IPv6 stubs (`ipv6_mod_enabled()` returns false, so wireguard never opens a v6 socket) | `udp_sock_create6`, `udp_tunnel6_xmit_skb`, `ipv6_chk_addr`, `dst_cache_get_ip6/set_ip6` |
| substitution | `ktime_get_coarse_with_offset` → exported `ktime_get_with_offset` |

**Key gotcha:** `CONFIG_TRIM_UNUSED_KSYMS` also filters `EXPORT_SYMBOL()`
inside out-of-tree modules (via `__KSYM_<name>` checks in `linux/export.h`),
so `wg_shim.c` force-defines `__KSYM_<name> 1` for every export *before any
include*. Without that the module builds fine but its ksymtab is empty.

## Usage (on the Wii)

```sh
# build (small single file; native build on the Wii is fine)
cd /root/wg_shim
make -C /lib/modules/$(uname -r)/build M=$PWD modules

# load shim (resolves trampoline addresses from /proc/kallsyms) + wireguard
sh wg_load.sh

# regular wireguard from here on
ip link add dev wg0 type wireguard
wg set wg0 listen-port 51820 private-key ... peer ...
ip addr add 10.99.0.2/24 dev wg0 && ip link set wg0 up
```

`wg_mac_up.sh` brings up the macOS side (wireguard-go + wg, via sudo).

## Measured result (2026-07-04, Wii ↔ Mac over LAN, iperf3)

| direction | throughput |
|---|---|
| Wii → Mac (Wii encrypts) | **37.4 Mbit/s (~4.7 MB/s)** — ~90% of the Wii's raw-TCP ceiling (5.3 MB/s) |
| Mac → Wii (Wii decrypts) | **7.2 Mbit/s (~0.9 MB/s)** |

For comparison, the userspace smoltcp netstack path topped out around
~29 KB/s on the same hardware: kernel WireGuard is 30–160× faster and makes
single-device tailnet use practical, pending control-plane integration.
