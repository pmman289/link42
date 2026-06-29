# udp2raw systemd template units

This provides `wg-quick@`-style instance units:

- `udp2raw-server@NAME.service` reads `NAME` from `/etc/udp2raw/server`
- `udp2raw-client@NAME.service` reads `NAME` from `/etc/udp2raw/client`

## Install

```sh
install -Dm755 systemd/udp2raw-systemd /usr/local/libexec/udp2raw-systemd
install -Dm644 systemd/udp2raw-server@.service /etc/systemd/system/udp2raw-server@.service
install -Dm644 systemd/udp2raw-client@.service /etc/systemd/system/udp2raw-client@.service
systemctl daemon-reload
```

## Configure

Create the mapping files:

```sh
mkdir -p /etc/udp2raw
```

Example `/etc/udp2raw/server`:

```conf
homelab -s -l0.0.0.0:23002 -r127.0.0.1:12312 -k "639768" --raw-mode faketcp --cipher-mode xor -a
```

Example `/etc/udp2raw/client`:

```conf
homelab -c -l127.0.0.1:12312 -rSERVER_IP:23002 -k "639768" --raw-mode faketcp --cipher-mode xor -a
```

The separator after the instance name can also be `=`:

```conf
homelab = -s -l0.0.0.0:23002 -r127.0.0.1:12312 -k "639768" --raw-mode faketcp --cipher-mode xor -a
```

## Use

```sh
systemctl enable --now udp2raw-server@homelab
systemctl status udp2raw-server@homelab
```

For a client:

```sh
systemctl enable --now udp2raw-client@homelab
systemctl status udp2raw-client@homelab
```
