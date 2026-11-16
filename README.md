# Drone Doctor for CORE

This workspace contains the scenario scripts directly in this directory. It also includes the CORE XML topology (`drone-doctor-core.xml`), the walkthrough in `docs/`, the original transfer files in `archives/`, and CORE 9.2.1 source with its Python dependency lockfiles in `dependencies/core/`. See [DEPENDENCIES.md](DEPENDENCIES.md) for setup and the dependency inventory.

The scripts and configuration in this directory are the current versions. The ZIP and ISO in `archives/` are historical transfer artifacts and do not include later fixes. `SHA256SUMS` records the original transfer, so files changed since then will not match it.

Drone Doctor is a four-node network-emulation lab for autonomous intrusion detection, temporary containment, and service recovery. A separate CORE router connects a fixed lab client to Drone 1’s external TCP port 80. Each drone’s Python service serves mutually authenticated HTTPS on port 443 on the mission WLAN.

## Run the lab

Use a Linux host with CORE 9.2.1 or a compatible CORE gRPC API, its Python client, a running local CORE daemon, Docker Engine with cgroup v2, and OpenSSL 3. CORE and the runner must use the same local Docker daemon. The host kernel needs nftables and NFQUEUE. Use the Python environment that ships with your CORE installation. Build the image while package repositories are reachable, or pre-stage the built image on the lab host.

```sh
docker build -t drone-doctor:lab .
python3 scenario.py --preflight
python3 scenario.py --case firewall
python3 scenario.py --case all
```

The preflight checks CORE gRPC, Docker image availability, resource limits, and whether Suricata can attach to an actual NFQUEUE in a disposable, disconnected container. CORE Docker nodes run with the privileges required by CORE’s networking. The scenario creates six disconnected containers, four drones plus a test client and router. It configures only emulated links, with no connection to the host’s physical network and no published Docker ports.

To watch the topology, open **Session → Sessions** in the CORE GUI and join the session ID printed by the runner. Run a single case with `--keep` to retain the session for inspection after the checks finish. Delete it through the Sessions dialog when done. Ordinary runs delete their session automatically.

## Cases and evidence

| Case | What the runner checks |
| --- | --- |
| `firewall` | A single attempt and its retransmission produce one observation. Three distinct attempts trigger a source-scoped 30-second firewall entry. A subsequent attempt increments its counter, then the entry expires. The app recovers after a deliberate process kill. Drone 4 goes out of range for eight seconds and its peers refresh its status after it comes back. |
| `decoy` | Three attempts activate a 60-second decoy when the mission service and memory budget are healthy. Ordinary HTTP gets a static reply. The IPS drops the harmless test URI. The path closes on lease expiry and on a deliberate IPS worker failure in a second activation. |
| `mixed` | A mission service crash overlaps the port 80 threshold. The agent chooses the firewall and recovers the app independently. |
| `pressure` | A synthetic memory-pressure signal forces the firewall branch even though the decoy is enabled. The guard also checks actual cgroup memory, with 512 MiB of headroom required to start or keep the decoy. |

For every case, the runner checks that a client with an untrusted TLS certificate is rejected and that the external client cannot access HTTPS. It continuously evaluates the authenticated mission health samples outside the explicitly injected fault windows. Three failed peer polls mark last-known peer status stale. Two successful polls restore it. The restart budget is two per minute.

Results are written under `runs/` or the path supplied by `--results`. Look in `summary.json` for per-case pass/fail checks, labeled decision counts, benign-case false blocks, recovery time, HTTPS check failures, and resource measurements. Case directories contain timestamped `timeline.jsonl`, Suricata EVE output, and process logs. An installed firewall action is verified by the subsequent packet counter. An installed decoy is verified with an ordinary request and a recorded IPS verdict.

## Compare the offline model with rules

Pre-stage the [Qwen2.5-0.5B-Instruct Q4_K_M GGUF](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/blob/main/qwen2.5-0.5b-instruct-q4_k_m.gguf) and a Linux CPU build of [llama.cpp](https://github.com/ggml-org/llama.cpp) that runs on Ubuntu 24.04. Put `llama-server` and any required adjacent shared libraries in the same directory. Build and download on a connected system if needed. Inference runs on loopback inside Drone 1 using the staged files.

```sh
python3 scenario.py --mode compare --case all \
  --llama-dir /path/to/llama-build/bin \
  --model-file /path/to/qwen2.5-0.5b-instruct-q4_k_m.gguf
```

The comparison repeats the cases with rules and model modes. The model receives structured evidence and the allowed action IDs. The Python agent validates its answer and uses rules within two seconds if inference stalls or fails. Health and peer checks run independently. The per-case reports include model fallbacks, peak cgroup memory, and peak CPU usage sampled at the health-check cadence. Rules are the default. The replayed traffic and synthetic failures establish lab behavior. Hardware power, RF behavior, flight-control failsafes, and real workload capacity require separate measurements.

## Offline checks

```sh
python3 -m unittest discover -s tests -v
```

The offline suite checks policy, recovery hysteresis and restart budget, certificate authentication, and real Suricata packet replay. The Suricata and OpenSSL checks skip if their binaries are unavailable. The source was also checked against the CORE 9.2.1 protobuf client. A later live CORE/Docker run of the firewall case passed its checks; the other cases and real llama.cpp inference have not been verified live.

- [CORE Docker nodes](https://coreemu.github.io/core/docker.html) · [CORE basic mobility](https://coreemu.github.io/core/tutorials/tutorial3.html)
- [Suricata EVE JSON format](https://docs.suricata.io/en/suricata-8.0.6/output/eve/eve-json-format.html) · [Suricata inline IPS](https://docs.suricata.io/en/suricata-8.0.4/ips/setting-up-ipsinline-for-linux.html)
- [PX4 companion-computer reference](https://docs.px4.io/main/en/companion_computer/holybro_pixhawk_rpi_cm4_baseboard) · [PX4 failsafe simulation](https://docs.px4.io/main/en/simulation/failsafes)
