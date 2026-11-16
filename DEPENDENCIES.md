# Setup and included dependencies

Run commands from `/home/dsch/drone_scenario`. The application scripts and tests use Python's standard library. Running the full scenario also requires CORE's Python package and gRPC dependencies in the interpreter used for `scenario.py`.

## Included files

| Location | Contents |
| --- | --- |
| `scenario.py` | CORE session creation, certificates, fixtures, acceptance checks, and result collection |
| `common.py`, `doctor.py`, `guard.py`, `policy.py`, `services.py`, `fixture.py` | Shared configuration, agent, containment, policy, mission service, and traffic fixtures |
| `Dockerfile`, `.dockerignore` | Ubuntu 24.04 node image and its package dependencies |
| `suricata.yaml`, `observe.rules`, `inline.rules` | Passive detection and inline IPS configuration |
| `tests/test_lab.py` | Offline policy, recovery, TLS, and Suricata replay tests |
| `drone-doctor-core.xml` | Four drones, router, client, and mission WLAN for the CORE GUI |
| `dependencies/core/` | Local CORE 9.2.1 source snapshot, BSD license, build scripts, protobuf definitions, and install documentation |
| `dependencies/core/daemon/pyproject.toml` | Authoritative Python dependency versions for the bundled CORE source |
| `dependencies/core/daemon/poetry.lock`, `dependencies/core/daemon/uv.lock` | Original CORE dependency lockfiles |
| `dependencies/provisioning/` | Original Debian 12 CORE setup and source-update scripts |
| `docs/Drone Doctor CORE Walkthrough.docx` | Original walkthrough |
| `archives/` | Original scenario ZIP and transfer ISO |
| `TRANSFER.json`, `SHA256SUMS` | Source provenance and checksums of the transferred files |

The XML supplies the topology. Use `scenario.py` to configure and exercise the mission services, credentials, agent, and traffic cases.

## Host runtime

- Linux with CORE 9.2.1, its local gRPC daemon (default port 50051), and its Python environment. The bundled CORE source requires Python 3.10 or newer; Python 3.11 is a practical match for its pinned dependencies.
- Docker Engine with cgroup v2. CORE and the runner must access the same local Docker daemon.
- OpenSSL 3 CLI for generating the short-lived lab certificates.
- Kernel networking support for bridges, veth, nftables, and NFQUEUE.
- Suricata and OpenSSL on the host to run every offline test. The runtime Suricata installation is supplied by the node image.

The Dockerfile installs `bash`, `ca-certificates`, `ethtool`, `iproute2`, `iputils-ping`, `libgomp1`, `nftables`, `procps`, `python3`, `suricata`, and `util-linux` inside the image.

Source and dependency declarations are bundled. OS packages, Python wheels, the Ubuntu base image, and a built `drone-doctor:lab` image are not bundled as an offline binary repository. Installing dependencies or building the image requires reachable package repositories or pre-staged caches.

## Launch with CORE already installed

Use the interpreter belonging to the working CORE installation. A common path is `/opt/core/venv/bin/python`; confirm it can import `core.api.grpc.client` before use.

```sh
cd /home/dsch/drone_scenario
docker build -t drone-doctor:lab .
/opt/core/venv/bin/python scenario.py --preflight
/opt/core/venv/bin/python scenario.py --case firewall --keep
```

Start the local CORE daemon first if it is not already running. Join the session ID printed by the runner from the CORE GUI's Sessions dialog. Run `--case all` for the full set of cases. Reports are written under `runs/`.

## Install CORE from the bundled source

The included instructions are in `dependencies/core/docs/install.md`. The source's standard installer can use this local snapshot:

```sh
cd /home/dsch/drone_scenario/dependencies/core
./setup.sh
export PATH="$HOME/.local/bin:$PATH"
inv install --no-ospf
```

These commands install system dependencies and CORE and require sudo and package repository access. OSPF and EMANE are unnecessary for this scenario's basic-range WLAN and explicitly configured router. The preserved scripts in `dependencies/provisioning/` are broader Debian VM provisioning tools; they also configure desktop software and users and fetch remote source. They have not been executed as part of this transfer.

## Optional model comparison

Rules mode needs no model. Model and comparison modes additionally require a Linux CPU `llama-server`, its adjacent shared libraries, and the Qwen2.5-0.5B-Instruct Q4_K_M GGUF described in `README.md`. These optional binary/model artifacts were not present in the original scenario package and are not included here. Supply them with `--llama-dir` and `--model-file`.

## Verification

```sh
python3 -m unittest discover -s tests -v
python3 scenario.py --help
```

After transfer, all nine offline tests passed, including TLS certificate checks and both real Suricata packet replay checks. A later live CORE/Docker firewall run also passed. The original `SHA256SUMS` documents the transfer snapshot and will report mismatches for files modified afterward.

The files were copied from the original workspace; the originals were retained. See `TRANSFER.json` for the source paths and CORE revision.
