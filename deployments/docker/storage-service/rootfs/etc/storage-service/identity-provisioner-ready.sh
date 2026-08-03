#!/bin/sh
# Waits for cmd/identity-provisioner (ST-F-11, KI-01) to finish its
# one-time provisionInitial setup before sshd is allowed to start -
# dependencies.d/identity-provisioner on this oneshot only guarantees that
# longrun has been STARTED by s6-rc, not that it has finished writing
# authorized-keys-command's own config/cert/key/CA-root files yet (same
# distinction already documented for tailscale-up.sh's own wait on
# tailscaled's control socket).
#
# Polling for authorized-keys-command.conf specifically is sufficient:
# services/storage-service/cmd/identity-provisioner/main.go's
# provisionInitial writes it LAST, after the CA root and the first
# certificate/key pair, precisely so its existence is this one signal.
#
# Not a hard requirement for correctness - a real SFTP connection attempt
# during this narrow startup window would just fail closed (RD-04) via
# authorized-keys-command's own config-load error path, then succeed on
# retry - but this oneshot removes that window entirely rather than
# accepting it.
set -eu

i=0
while [ ! -f /var/lib/storage-service-identity/authorized-keys-command.conf ]; do
	i=$((i + 1))
	if [ "$i" -ge 60 ]; then
		echo "identity-provisioner-ready: timed out waiting for /var/lib/storage-service-identity/authorized-keys-command.conf" >&2
		exit 1
	fi
	sleep 1
done
