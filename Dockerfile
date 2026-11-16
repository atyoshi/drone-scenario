FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates ethtool iproute2 iputils-ping libgomp1 nftables procps python3 suricata util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 18080 missionauth \
    && useradd --uid 18081 --gid missionauth --no-create-home doctor \
    && useradd --uid 18082 --gid missionauth --no-create-home mission \
    && useradd --uid 18083 --user-group --no-create-home decoy \
    && useradd --uid 18084 --user-group --no-create-home inference

WORKDIR /opt/drone-doctor
COPY common.py policy.py doctor.py guard.py services.py fixture.py suricata.yaml observe.rules inline.rules ./
