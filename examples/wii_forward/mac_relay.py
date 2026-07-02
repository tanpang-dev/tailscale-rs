#!/usr/bin/env python3
"""Mac relay: iPhone -(tailnet P2P)-> Mac:LISTEN -(LAN)-> Wii sshd.

Bypasses the Wii's tailscale-rs (DERP-only, preview smoltcp) so sustained
SFTP uploads from outside home stay stable. Transport-only; SSH auth is
end-to-end iPhone<->Wii.
"""
import socket
import sys
import threading

LISTEN_HOST = "100.75.230.127"   # Mac tailnet IP (fallback: 0.0.0.0)
LISTEN_PORT = 2222
DEST_HOST = "192.168.0.50"       # Wii LAN IP
DEST_PORT = 22


def pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client, addr):
    try:
        remote = socket.create_connection((DEST_HOST, DEST_PORT), timeout=10)
    except OSError as e:
        print(f"dial {DEST_HOST}:{DEST_PORT} failed for {addr}: {e}", flush=True)
        client.close()
        return
    print(f"conn {addr} -> {DEST_HOST}:{DEST_PORT}", flush=True)
    t1 = threading.Thread(target=pipe, args=(client, remote), daemon=True)
    t2 = threading.Thread(target=pipe, args=(remote, client), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client.close()
    remote.close()
    print(f"closed {addr}", flush=True)


def serve(bind_host):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_host, LISTEN_PORT))
    s.listen(64)
    print(f"listening {bind_host}:{LISTEN_PORT} -> {DEST_HOST}:{DEST_PORT}", flush=True)
    while True:
        client, addr = s.accept()
        threading.Thread(target=handle, args=(client, addr), daemon=True).start()


def main():
    try:
        serve(LISTEN_HOST)
    except OSError as e:
        print(f"bind {LISTEN_HOST} failed ({e}); falling back to 0.0.0.0", flush=True)
        serve("0.0.0.0")


if __name__ == "__main__":
    main()
