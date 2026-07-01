# Link42 Real E2E Harness

These helpers create a disposable real-machine controller plus two real agents.
They are intended for middleware, WireGuard, and uninstall regression testing
where dry-run tests are not enough.

Default topology used by the current test bench:

```text
controller: local machine
local agent: local machine
remote agent: ssh vpstest
local endpoint: 192.168.123.20
remote endpoint: 172.20.177.22
```

## Configure

Copy the example and adjust addresses, SSH host, and cleanup hints:

```bash
cp scripts/real-e2e/env.example /tmp/link42-real-e2e.env
$EDITOR /tmp/link42-real-e2e.env
```

Important cleanup fields:

```text
LINK42_REAL_LOCAL_WG_IFACES
LINK42_REAL_REMOTE_WG_IFACES
LINK42_REAL_LOCAL_MIMIC_IFACES
LINK42_REAL_REMOTE_MIMIC_IFACES
LINK42_REAL_PURGE_MIMIC
```

Set the interface lists before running tests that create real WireGuard or
mimic services. The cleanup script only removes interfaces and mimic configs
listed there, plus Link42 udp2raw assets/services created by the agent.

## Start

Build the web app when UI testing needs the controller to serve the latest
frontend:

```bash
npm run build --prefix apps/web
```

Bring up the disposable controller and both agents:

```bash
scripts/real-e2e/up.sh
```

The script writes state, logs, and a temp SQLite database under:

```text
/tmp/link42-real-e2e
```

It also prints the controller URL and node ids. The remote agent is started from
a tarball of the current `apps/agent` and `packages` directories, so it tests
the current working tree.

## Inspect

```bash
scripts/real-e2e/status.sh
```

This prints controller/agent processes, node status/capabilities, and recent
agent tasks from the temp SQLite database.

Useful manual checks during middleware testing:

```bash
systemctl is-active mimic@enp3s0.service
ssh vpstest 'systemctl is-active mimic@enp1s0.service'

wg show <local-test-interface>
ssh vpstest 'wg show <remote-test-interface>'

find /etc/link42/middleware -maxdepth 4 -type f -ls
ssh vpstest 'find /etc/link42/middleware -maxdepth 4 -type f -ls'
```

## Browser Tests

Use the persistent Playwright runner:

```bash
scripts/e2e/run-playwright.sh /tmp/link42-my-test.js
```

Point scripts at the controller printed by `up.sh`, normally:

```text
http://127.0.0.1:8016/
```

## Cleanup

```bash
scripts/real-e2e/down.sh
```

Cleanup stops the temp controller/agents, removes configured test WireGuard
interfaces/configs, removes configured mimic service configs, removes Link42
udp2raw assets/services, and deletes the run directory.

If the test installed mimic packages and you want the machines back to the
pre-test state:

```bash
LINK42_REAL_PURGE_MIMIC=1 scripts/real-e2e/down.sh
```

Do not put production interface names into the cleanup lists.
