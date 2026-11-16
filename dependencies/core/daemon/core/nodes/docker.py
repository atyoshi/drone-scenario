import json
import logging
import os
import shlex
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING

import yaml
from mako.template import Template

from core import utils
from core.emulator.distributed import DistributedServer
from core.errors import CoreCommandError, CoreError
from core.executables import BASH
from core.nodes.base import CoreNode, CoreNodeOptions

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from core.emulator.session import Session

DOCKER: str = "docker"
DOCKER_COMPOSE: str = os.environ.get("DOCKER_COMPOSE", "docker compose")
COMPAT_BUILD_NETWORK: str = "host"
# how long to wait for a started container to report a usable init pid, and
# how long to sleep between polls, see DockerNode._wait_for_pid
PID_WAIT_TIMEOUT: float = 90.0
PID_WAIT_DELAY: float = 0.5


@dataclass
class DockerOptions(CoreNodeOptions):
    services: list[str] = field(default_factory=lambda: ["DefaultRoute"])
    image: str = "ubuntu"
    """image used when creating container"""
    binds: list[tuple[str, str]] = field(default_factory=list)
    """bind mount source and destinations to setup within container"""
    volumes: list[tuple[str, str, bool, bool]] = field(default_factory=list)
    """
    volume mount source, destination, unique, delete to setup within container

    unique is True for node unique volume naming
    delete is True for deleting volume mount during shutdown
    """
    compose: str = None
    """
    Path to a compose file, if one should be used for this node.
    """
    compose_name: str = None
    """
    Service name to start, within the provided compose file.
    """
    image_compatibility: bool = False
    docker_command: str = "tail -f /dev/null"
    run_image_default: bool = False


@dataclass
class DockerVolume:
    src: str
    """volume mount name"""
    dst: str
    """volume mount destination directory"""
    unique: bool = True
    """True to create a node unique prefixed name for this volume"""
    delete: bool = True
    """True to delete the volume during shutdown"""
    path: str = None
    """path to the volume on the host"""


class DockerNode(CoreNode):
    """
    Provides logic for creating a Docker based node.
    """

    def __init__(
        self,
        session: "Session",
        _id: int = None,
        name: str = None,
        server: DistributedServer = None,
        options: DockerOptions = None,
    ) -> None:
        """
        Create a DockerNode instance.

        :param session: core session instance
        :param _id: node id
        :param name: node name
        :param server: remote server node
            will run on, default is None for localhost
        :param options: options for creating node
        """
        options = options or DockerOptions()
        super().__init__(session, _id, name, server, options)
        self.image: str = options.image
        self.compose: str | None = options.compose
        self.compose_name: str | None = options.compose_name
        self.image_compatibility: bool = options.image_compatibility
        self.docker_command: str = options.docker_command
        self.run_image_default: bool = options.run_image_default
        self.binds: list[tuple[str, str]] = options.binds
        self.volumes: dict[str, DockerVolume] = {}
        self.env: dict[str, str] = {}
        self.runtime_container: str = self.name
        self.compose_files: list[str] = []
        # Shell used for `shell=True` commands inside this container. Resolved
        # against the running image in startup(); see _resolve_shell.
        self.shell: str = BASH
        for src, dst, unique, delete in options.volumes:
            src_name = self._unique_name(src) if unique else src
            self.volumes[src] = DockerVolume(src_name, dst, unique, delete)

    @classmethod
    def create_options(cls) -> DockerOptions:
        """
        Return default creation options, which can be used during node creation.

        :return: docker options
        """
        return DockerOptions()

    def create_cmd(self, args: str, shell: bool = False) -> str:
        """
        Create command used to run commands within the context of a node.

        :param args: command arguments
        :param shell: True to run shell like, False otherwise
        :return: node command
        """
        if shell:
            args = f"{self.shell} -c {shlex.quote(args)}"
        return f"{DOCKER} exec {self.runtime_container} {args}"

    def _resolve_runtime_container(self) -> str:
        """
        Resolve actual runtime container object for compose services.

        :return: container id/name to use for inspect/exec
        :raises CoreError: when compose service has no running container
        """
        if not self.compose:
            return self.name
        container = self.host_cmd(
            f"{DOCKER_COMPOSE} {self._compose_args()} ps -q "
            f"{shlex.quote(self.compose_name)}",
            cwd=self.directory,
        ).strip()
        if not container:
            raise CoreError(
                f"compose service has no running container: {self.compose_name}"
            )
        return container

    def _wait_for_pid(self, timeout: float = PID_WAIT_TIMEOUT) -> tuple[int, str]:
        """
        Wait for the runtime container to report a usable init pid.

        ``docker run -td`` and ``docker compose up -d`` return once the request
        is accepted, which is before the container's init process is guaranteed
        to have a pid. Until then ``.State.Pid`` is ``0``, and reading
        ``/proc/0/environ`` fails outright. Reading the environment is used here
        as the readiness test rather than the pid alone, because both come from
        the same condition -- init actually running -- and checking them
        separately just reopens the race in the gap between the two calls.

        Retrying matters well beyond this method: an exception raised here
        propagates out of the session's startup threadpool, so a single unlucky
        poll fails the node and leaves the whole session stuck in configuration
        state, never reaching runtime.

        :param timeout: seconds to wait for the container's init pid
        :return: the container's init pid and its process environment
        :raises CoreError: when no usable pid appears within the timeout
        """
        deadline = time.monotonic() + timeout
        while True:
            pid = int(
                self.host_cmd(
                    f"{DOCKER} inspect -f '{{{{.State.Pid}}}}' "
                    f"{self.runtime_container}"
                ).strip()
                or 0
            )
            if pid:
                try:
                    return pid, self.host_cmd(f"cat /proc/{pid}/environ")
                except CoreCommandError:
                    # container exited between the inspect and the read, most
                    # likely restarting; fall through and poll for its new pid
                    logger.debug(
                        "node(%s) pid(%s) went away before its environment "
                        "could be read, retrying",
                        self.name,
                        pid,
                    )
            if time.monotonic() >= deadline:
                raise CoreError(
                    f"node({self.name}) container did not report a usable pid "
                    f"within {timeout} seconds"
                )
            time.sleep(PID_WAIT_DELAY)

    def _resolve_shell(self) -> str:
        """
        Pick the shell to use for ``shell=True`` commands in this container.

        A Docker node runs whatever image the scenario names, and bash is not
        a given: Alpine, busybox and distroless based images commonly ship only
        ``/bin/sh``. Running ``docker exec <node> bash -c ...`` against one of
        those fails with ``exec: "bash": no such file or directory``, which
        takes down every service that uses a shell command -- silently, since
        service startup failures do not stop the node from coming up. The node
        then looks healthy while doing none of the work it was configured for.

        Prefers bash where it exists, so service templates written against bash
        keep working, and falls back to the POSIX shell otherwise. If neither
        probe succeeds, bash is kept so the resulting error reports the
        original, more recognizable missing-bash failure.

        :return: shell executable to use inside this container
        """
        for candidate in (BASH, "sh"):
            try:
                self.host_cmd(
                    f"{DOCKER} exec {self.runtime_container} {candidate} -c true"
                )
                return candidate
            except CoreCommandError:
                logger.debug(
                    "node(%s) shell(%s) unavailable in image", self.name, candidate
                )
        logger.warning(
            "node(%s) found neither bash nor sh; shell commands will likely fail",
            self.name,
        )
        return BASH

    @staticmethod
    def _parse_environ(output: str) -> dict[str, str]:
        """
        Parse ``/proc/<pid>/environ`` contents into a mapping.

        The kernel exposes this region as NUL-separated ``KEY=VALUE`` pairs,
        but that shape cannot be relied on: the region is ordinary process
        memory and a process may overwrite it. nginx does exactly that,
        rewriting it to hold its process title, so an nginx container's
        environ reads back as ``" nginx -g daemon off;"`` and padding, with no
        pairs at all.

        Entries without a ``=`` are therefore skipped rather than treated as an
        error. Raising here is not a survivable option: this runs during node
        startup inside the session's threadpool, so the exception strands the
        whole session in configuration state, and it reports as an unrelated
        "CORE never finished instantiating <routers>" much later. An
        environment CORE could not parse is worth losing; the session is not.

        :param output: raw contents of ``/proc/<pid>/environ``
        :return: parsed environment variables, possibly empty
        """
        env: dict[str, str] = {}
        for entry in output.split("\x00"):
            key, sep, value = entry.partition("=")
            if sep and key:
                env[key] = value
        return env

    def cmd(self, args: str, wait: bool = True, shell: bool = False) -> str:
        """
        Runs a command within the context of the Docker node.

        :param args: command to run
        :param wait: True to wait for status, False otherwise
        :param shell: True to use shell, False otherwise
        :return: combined stdout and stderr
        :raises CoreCommandError: when a non-zero exit status occurs
        """
        args = self.create_cmd(args, shell)
        if self.server is None:
            return utils.cmd(args, wait=wait, shell=shell, env=self.env)
        else:
            return self.server.remote_cmd(args, wait=wait, env=self.env)

    def cmd_perf(self, args: str, wait: bool = True, shell: bool = False) -> str:
        """
        Runs a command within the Docker node using nsenter to avoid
        client/server overhead.

        :param args: command to run
        :param wait: True to wait for status, False otherwise
        :param shell: True to use shell, False otherwise
        :return: combined stdout and stderr
        :raises CoreCommandError: when a non-zero exit status occurs
        """
        if shell:
            args = f"{BASH} -c {shlex.quote(args)}"
        args = f"nsenter -t {self.pid} -m -u -i -p -n -- {args}"
        if self.server is None:
            return utils.cmd(args, wait=wait, shell=shell, env=self.env)
        else:
            return self.server.remote_cmd(args, wait=wait, env=self.env)

    def create_net_cmd(self, args: str, shell: bool = False) -> str:
        """
        Create command used to run network commands within the context of a node.

        :param args: command arguments
        :param shell: True to run shell like, False otherwise
        :return: node command
        """
        if shell:
            args = f"{BASH} -c {shlex.quote(args)}"
        return f"nsenter -t {self.pid} -n -- {args}"

    def net_cmd(self, args: str, wait: bool = True, shell: bool = False) -> str:
        """
        Runs a command that is used to configure and setup the network within a
        node.

        :param args: command to run
        :param wait: True to wait for status, False otherwise
        :param shell: True to use shell, False otherwise
        :return: combined stdout and stderr
        :raises CoreCommandError: when a non-zero exit status occurs
        """
        args = self.create_net_cmd(args, shell)
        if self.server is None:
            return utils.cmd(args, wait=wait, shell=shell, env=self.env)
        else:
            return self.server.remote_cmd(args, wait=wait, env=self.env)

    def _unique_name(self, name: str) -> str:
        """
        Creates a session/node unique prefixed name for the provided input.

        :param name: name to make unique
        :return: unique session/node prefixed name
        """
        return f"{self.session.id}.{self.id}.{name}"

    @classmethod
    def container_exists(cls, name: str) -> bool:
        """Return whether a local Docker container has the exact given name."""
        name_filter = shlex.quote(f"name=^/{name}$")
        output = utils.cmd(f"{DOCKER} container ls -aq --filter {name_filter}")
        return bool(output.strip())

    @classmethod
    def remove_container(cls, name: str) -> None:
        """Force-remove a local Docker container by name."""
        utils.cmd(f"{DOCKER} rm -f {shlex.quote(name)}")

    @classmethod
    def compatibility_image_name(
        cls, session_id: int, node_id: int, node_name: str
    ) -> str:
        """Return the compatibility image tag for a session node."""
        value = f"core-compat-{session_id}-{node_id}-{node_name}".lower()
        name = "".join(c if c.isalnum() or c in "._-" else "-" for c in value)
        return f"{name}:latest"

    @classmethod
    def image_exists(cls, name: str) -> bool:
        """Return whether a local Docker image has the exact given tag."""
        output = utils.cmd(f"{DOCKER} image ls -q {shlex.quote(name)}")
        return bool(output.strip())

    @classmethod
    def remove_image(cls, name: str) -> None:
        """Force-remove a local Docker image by tag."""
        utils.cmd(f"{DOCKER} image rm -f {shlex.quote(name)}")

    def should_check_image_compatibility(self) -> bool:
        return self.image_compatibility

    def _write_host_file(self, file_path: Path, contents: str) -> None:
        self.host_cmd(
            f"printf %s {shlex.quote(contents)} > {shlex.quote(str(file_path))}",
            shell=True,
        )

    def _prepare_compose_project(self, compose_path: str, rendered: str) -> Path:
        compose_file = Path(compose_path)
        source_dir = compose_file.parent or Path(".")
        if self.server is None:
            src_dir = source_dir.resolve()
            dst_dir = self.directory.resolve()
            if src_dir != dst_dir:
                shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True, symlinks=True)
        else:
            src_dir = shlex.quote(str(source_dir))
            dst_dir = shlex.quote(str(self.directory))
            self.host_cmd(
                f"src_dir=$(cd {src_dir} && pwd -P) && "
                f"dst_dir=$(cd {dst_dir} && pwd -P) && "
                'if [ "$src_dir" != "$dst_dir" ]; then cp -a "$src_dir"/. "$dst_dir"/; fi',
                shell=True,
            )
        compose_file = self.directory / compose_file.name
        self._write_host_file(compose_file, rendered)
        return compose_file

    def _compose_args(self) -> str:
        """
        Return common Compose options for this node's project.

        Deliberately does *not* pass ``--project-name``, so Compose derives the
        project from the working directory it is run in -- the node directory,
        ``<node>.conf``, giving ``<node>conf``. That default is already unique
        per node within a session, and an explicit per-node name is not the
        thing that makes concurrent sessions safe: compose files here pin
        ``container_name``, which is global to the daemon, so two sessions each
        holding a ``docker-8`` collide on the container name regardless of
        project.

        What the default *does* buy is a stable, predictable name that tooling
        preparing a node's compose resources ahead of CORE can target. Anything
        that pre-creates this node's container or named volumes must use the
        same project, or Compose treats them as a different project's
        resources: the container name conflicts ("Conflict. The container name
        \"/docker-8\" is already in use") and, worse, project-scoped named
        volumes silently resolve to new empty ones, so pre-populated volume
        contents vanish without an error.
        """
        return " ".join(
            option
            for compose_file in self.compose_files
            for option in ("-f", shlex.quote(compose_file))
        )

    def _compose_core_network(self, rendered: str) -> str:
        """Put all Compose services in the selected service's CORE namespace.

        Compose normally gives every service a Docker bridge interface. CORE nodes
        must instead receive their sole data-plane interface from the emulation.
        The selected service starts with no Docker network; every other service
        shares that namespace and is reachable by its service name on loopback.
        """
        data = yaml.safe_load(rendered) or {}
        services = data.get("services") or {}
        target = services.get(self.compose_name)
        if not target:
            raise CoreError(f"compose service not found: {self.compose_name}")

        target["network_mode"] = "none"
        target.pop("networks", None)
        target.pop("depends_on", None)
        target.pop("ports", None)

        def normalize_extra_hosts(value) -> dict[str, str]:
            if isinstance(value, dict):
                return dict(value)
            if not isinstance(value, list):
                return {}
            hosts = {}
            for entry in value:
                if not isinstance(entry, str):
                    continue
                if "=" in entry:
                    host, address = entry.split("=", 1)
                elif ":" in entry:
                    host, address = entry.split(":", 1)
                else:
                    continue
                hosts[host] = address
            return hosts

        target_hosts = normalize_extra_hosts(target.get("extra_hosts"))
        for service_name, service in services.items():
            if service_name == self.compose_name:
                continue
            target_hosts.setdefault(service_name, "127.0.0.1")
            # Docker does not allow extra_hosts together with
            # network_mode: service:<name>.
            service.pop("extra_hosts", None)
            service["network_mode"] = f"service:{self.compose_name}"
            service.pop("networks", None)
            service.pop("ports", None)
        target["extra_hosts"] = target_hosts
        return yaml.safe_dump(data, sort_keys=False)

    def _compatible_image_name(self) -> str:
        return self.compatibility_image_name(self.session.id, self.id, self.name)

    def _reuse_compatibility_image(self) -> bool:
        images = getattr(self.session, "reuse_compatibility_images", set())
        return self._compatible_image_name() in images

    def _image_user(self, image: str) -> str | None:
        quoted_image = shlex.quote(image)
        try:
            return self._inspect_image_user(quoted_image)
        except CoreCommandError:
            try:
                self.host_cmd(f"{DOCKER} pull {quoted_image}")
                return self._inspect_image_user(quoted_image)
            except CoreCommandError:
                logger.warning(
                    "node(%s) failed to inspect image user: %s", self.name, image
                )
                return None

    def _inspect_image_user(self, quoted_image: str) -> str | None:
        user = self.host_cmd(
            f"{DOCKER} image inspect -f '{{{{.Config.User}}}}' {quoted_image}"
        ).strip()
        return user or None

    def _volume_mountpoint(self, volume: DockerVolume) -> str:
        """Return a volume mountpoint suitable for use in shell commands."""
        return self.host_cmd(
            f"{DOCKER} volume inspect -f '{{{{.Mountpoint}}}}' {volume.src}"
        ).strip()

    def _compatibility_dockerfile(self, image: str) -> str:
        if "\n" in image or "\r" in image:
            raise CoreError(f"invalid image name: {image!r}")
        user = self._image_user(image)
        install_cmd = (
            "if command -v apt-get >/dev/null 2>&1; then "
            "apt_update() { apt-get -o Acquire::Check-Valid-Until=false update; }; "
            "apt_fix_sources() { "
            "for source in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do "
            "[ -f $source ] || continue; "
            "sed -i "
            "-e 's|https://deb.debian.org/debian|http://archive.debian.org/debian|g' "
            "-e 's|http://deb.debian.org/debian|http://archive.debian.org/debian|g' "
            "-e 's|https://security.debian.org/debian-security|http://archive.debian.org/debian-security|g' "
            "-e 's|http://security.debian.org/debian-security|http://archive.debian.org/debian-security|g' "
            "-e 's|https://security.debian.org|http://archive.debian.org|g' "
            "-e 's|http://security.debian.org|http://archive.debian.org|g' "
            "-e 's|https://ftp.debian.org/debian|http://archive.debian.org/debian|g' "
            "-e 's|http://ftp.debian.org/debian|http://archive.debian.org/debian|g' "
            "-e 's|https://archive.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' "
            "-e 's|http://archive.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' "
            "-e 's|https://security.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' "
            "-e 's|http://security.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' "
            "-e 's|https://ports.ubuntu.com/ubuntu-ports|http://old-releases.ubuntu.com/ubuntu|g' "
            "-e 's|http://ports.ubuntu.com/ubuntu-ports|http://old-releases.ubuntu.com/ubuntu|g' "
            "-e '/^[[:space:]]*deb .*archive\\.debian\\.org\\/debian [^[:space:]]*-updates[[:space:]]/d' "
            "-e '/^[[:space:]]*deb-src .*archive\\.debian\\.org\\/debian [^[:space:]]*-updates[[:space:]]/d' "
            "$source; done; }; "
            "if ! apt_update; then apt_fix_sources; apt_update; fi && "
            "DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-unauthenticated "
            "--force-yes --no-install-recommends "
            "bash iproute2 iputils-ping ethtool && rm -rf /var/lib/apt/lists/*; "
            "elif command -v apk >/dev/null 2>&1; then "
            "apk add --no-cache bash iproute2 iputils ethtool; "
            "elif command -v yum >/dev/null 2>&1; then "
            "yum install -y bash iproute iputils ethtool && yum clean all; "
            "else echo 'no supported package manager found' >&2; exit 1; fi"
        )
        lines = [
            f"FROM {image}",
            "USER root",
            f"RUN {json.dumps(['/bin/sh', '-euxc', install_cmd])}",
        ]
        if user:
            lines.append(f"USER {user}")
        return "\n".join(lines) + "\n"

    def setup_image_compatibility(self) -> None:
        image = self._compatible_image_name()
        if self._reuse_compatibility_image():
            self.image = image
            return
        dockerfile_path = self.directory / "Dockerfile.corecompat"
        self._write_host_file(
            dockerfile_path, self._compatibility_dockerfile(self.image)
        )
        self.host_cmd(
            f"{DOCKER} build --network {shlex.quote(COMPAT_BUILD_NETWORK)} "
            f"-t {shlex.quote(image)} -f Dockerfile.corecompat .",
            cwd=self.directory,
        )
        self.image = image

    def _compose_image_compatibility_override(self, rendered: str) -> Path | None:
        data = yaml.safe_load(rendered) or {}
        services = data.get("services") or {}
        service = services.get(self.compose_name) or {}
        image = service.get("image")
        if not image:
            logger.warning(
                "node(%s) compose service(%s) has no image to prepare",
                self.name,
                self.compose_name,
            )
            return None

        dockerfile_path = self.directory / "Dockerfile.corecompat"
        compatible_image = self._compatible_image_name()
        override = {
            "services": {
                self.compose_name: {
                    "image": compatible_image,
                }
            }
        }
        if not self._reuse_compatibility_image():
            self._write_host_file(
                dockerfile_path, self._compatibility_dockerfile(image)
            )
            override["services"][self.compose_name]["build"] = {
                "context": ".",
                "dockerfile": dockerfile_path.name,
                "network": COMPAT_BUILD_NETWORK,
            }
        override_path = self.directory / "docker-compose.corecompat.yml"
        self._write_host_file(override_path, yaml.safe_dump(override, sort_keys=False))
        return override_path

    def alive(self) -> bool:
        """
        Check if the node is alive.

        :return: True if node is alive, False otherwise
        """
        try:
            running = self.host_cmd(
                f"{DOCKER} inspect -f '{{{{.State.Running}}}}' {self.runtime_container}"
            )
            return json.loads(running)
        except CoreCommandError:
            return False

    def startup(self) -> None:
        """
        Create a docker container instance for the specified image.

        :return: nothing
        """
        with self.lock:
            if self.up:
                raise CoreError(f"starting node({self.name}) that is already up")
            # create node directory
            self.makenodedir()
            hostname = self.name.replace("_", "-")
            startup_command = (self.docker_command or "").strip()
            if self.compose:
                if not self.compose_name:
                    raise CoreError(
                        "a compose name is required when using a compose file"
                    )
                compose_path = os.path.expandvars(self.compose)
                data = self.host_cmd(f"cat {compose_path}")
                template = Template(data)
                rendered = template.render_unicode(
                    node=self,
                    hostname=hostname,
                    docker=DOCKER,
                    docker_compose=DOCKER_COMPOSE,
                )
                rendered = self._compose_core_network(rendered)
                compose_path = self._prepare_compose_project(compose_path, rendered)
                self.compose_files = [compose_path.name]
                if self.should_check_image_compatibility():
                    override_path = self._compose_image_compatibility_override(rendered)
                    if override_path:
                        self.compose_files.append(override_path.name)
                self.host_cmd(
                    f"{DOCKER_COMPOSE} {self._compose_args()} up -d",
                    cwd=self.directory,
                )
                self.runtime_container = self._resolve_runtime_container()
            else:
                if self.should_check_image_compatibility():
                    self.setup_image_compatibility()
                # setup commands for creating bind/volume mounts
                binds = ""
                for src, dst in self.binds:
                    binds += f"--mount type=bind,source={src},target={dst} "
                volumes = ""
                for volume in self.volumes.values():
                    volumes += (
                        f"--mount type=volume,"
                        f"source={volume.src},target={volume.dst} "
                    )
                # create container and retrieve the created containers PID
                cmd = "tail -f /dev/null"
                if self.run_image_default:
                    # Keep the container alive while interfaces are adopted,
                    # then launch ENTRYPOINT/CMD after startup.
                    logger.info(
                        "node(%s) run_image_default enabled, using keepalive anchor",
                        self.name,
                    )
                elif startup_command:
                    logger.info(
                        "node(%s) will run startup command after boot: %s",
                        self.name,
                        startup_command,
                    )

                run_cmd = (
                    f"{DOCKER} run -td --init --net=none --hostname {hostname} "
                    f"--name {self.name} --sysctl net.ipv6.conf.all.disable_ipv6=0 "
                    f"{binds} {volumes} "
                    f"--privileged {self.image} {cmd}"
                )
                self.host_cmd(run_cmd)

                running = self.host_cmd(
                    f"{DOCKER} inspect -f '{{{{.State.Running}}}}' {self.name}"
                ).strip().lower()
                if running != "true":
                    logger.warning(
                        "node(%s) container exited immediately; recreating with keepalive",
                        self.name,
                    )
                    self.host_cmd(f"{DOCKER} rm -f {self.name}")
                    keepalive_cmd = (
                        f"{DOCKER} run -td --init --net=none --hostname {hostname} "
                        f"--name {self.name} --sysctl net.ipv6.conf.all.disable_ipv6=0 "
                        f"{binds} {volumes} "
                        f"--privileged {self.image} tail -f /dev/null"
                    )
                    self.host_cmd(keepalive_cmd)
                # setup symlinks for bind and volume mounts within
                for src, dst in self.binds:
                    link_path = self.host_path(Path(dst), True)
                    self.host_cmd(f"ln -s {src} {link_path}")
                for volume in self.volumes.values():
                    volume.path = self._volume_mountpoint(volume)
                    link_path = self.host_path(Path(volume.dst), True)
                    self.host_cmd(f"ln -s {volume.path} {link_path}")
                self.runtime_container = self.name
            # retrieve pid and process environment for use in nsenter commands
            self.pid, output = self._wait_for_pid()
            self.env.update(self._parse_environ(output))
            # `cmd`/`net_cmd` pass this to Popen(env=...), which replaces the
            # environment outright instead of merging into the daemon's. The
            # binaries those run (nsenter, ip, ethtool) are host binaries --
            # only the network namespace is the container's -- so they need a
            # PATH to be found at all. A container whose environ yields no
            # PATH (see _parse_environ) would otherwise leave it unset and
            # every such command would fail with status 127.
            self.env.setdefault("PATH", os.environ.get("PATH") or os.defpath)
            # Resolved before services boot, since they are the main consumer
            # of shell commands and a wrong choice fails them silently.
            self.shell = self._resolve_shell()
            logger.debug("node(%s) pid: %s shell: %s", self.name, self.pid, self.shell)
            self.up = True
            if self.run_image_default:
                self.run_default_command()
            elif startup_command and not self.compose:
                self.run_startup_command(startup_command)

    def run_startup_command(self, command: str) -> None:
        """
        Run configured startup command string within the running container.
        """
        try:
            wrapped = shlex.quote(f"{command} > /tmp/core-startup.log 2>&1")
            self.host_cmd(f"{DOCKER} exec -d {self.runtime_container} sh -c {wrapped}")
            logger.info(
                "node(%s) startup command launched (see /tmp/core-startup.log)",
                self.name,
            )
        except Exception as e:
            logger.error("node(%s) failed startup command launch: %s", self.name, e)

    def run_default_command(self) -> None:
        """
        Inspects the image and runs its default ENTRYPOINT/CMD.
        """
        logger.info("node(%s) attempting to run image default command", self.name)
        try:
            image = self.image
            if not image:
                # for compose, try to find image from running container
                image = self.host_cmd(
                    f"{DOCKER} inspect -f '{{{{.Config.Image}}}}' {self.runtime_container}"
                ).strip()
                logger.info("node(%s) discovered image: %s", self.name, image)
            
            if not image:
                logger.warning("node(%s) could not determine image for default command", self.name)
                return

            # get image config
            data = self.host_cmd(f"{DOCKER} inspect -f '{{{{json .Config}}}}' {image}")
            config = json.loads(data)
            entrypoint = config.get("Entrypoint") or []
            cmd = config.get("Cmd") or []
            
            # handle case where entrypoint/cmd might be None or not list
            if not isinstance(entrypoint, list):
                entrypoint = [entrypoint] if entrypoint else []
            if not isinstance(cmd, list):
                cmd = [cmd] if cmd else []

            full_cmd = entrypoint + cmd
            if full_cmd:
                cmd_str = " ".join(shlex.quote(x) for x in full_cmd)
                logger.info("node(%s) running default command: %s", self.name, cmd_str)
                try:
                    self.host_cmd(f"{DOCKER} exec -d {self.runtime_container} {cmd_str}")
                    logger.info("node(%s) default command launched", self.name)
                except Exception as e:
                    logger.error("node(%s) failed to launch default command: %s", self.name, e)
            else:
                logger.warning("node(%s) image %s has no default ENTRYPOINT or CMD", self.name, image)
        except Exception as e:
            logger.error("node(%s) failed to run default command: %s", self.name, e)

    def shutdown(self) -> None:
        """
        Shutdown logic.

        :return: nothing
        """
        # nothing to do if node is not up
        if not self.up:
            return
        with self.lock:
            self.ifaces.clear()
            if self.compose:
                try:
                    self.host_cmd(
                        f"{DOCKER_COMPOSE} {self._compose_args()} down "
                        "--remove-orphans -t 0",
                        cwd=self.directory,
                    )
                except CoreCommandError:
                    logger.exception(
                        "node(%s) compose down failed, forcing container cleanup",
                        self.name,
                    )
                # Best-effort fallback for stale containers that survive compose down.
                containers = {self.name, self.runtime_container}
                for container in containers:
                    if container:
                        self.host_cmd(
                            f"{DOCKER} rm -f {container} >/dev/null 2>&1 || true",
                            shell=True,
                        )
            else:
                self.host_cmd(f"{DOCKER} rm -f {self.name}")
                for volume in self.volumes.values():
                    if volume.delete:
                        self.host_cmd(f"{DOCKER} volume rm {volume.src}")
            self.runtime_container = self.name
            self.up = False

    def termcmdstring(self, sh: str = "/bin/sh") -> str:
        """
        Create a terminal command string.

        :param sh: shell to execute command in
        :return: str
        """
        terminal = f"{DOCKER} exec -it {self.name} {sh}"
        if self.server is None:
            return terminal
        else:
            return f"ssh -X -f {self.server.host} xterm -e {terminal}"

    def create_dir(self, dir_path: Path) -> None:
        """
        Create a private directory.

        :param dir_path: path to create
        :return: nothing
        """
        logger.debug("creating node dir: %s", dir_path)
        self.cmd(f"mkdir -p {dir_path}")

    def mount(self, src_path: str, target_path: str) -> None:
        """
        Create and mount a directory.

        :param src_path: source directory to mount
        :param target_path: target directory to create
        :return: nothing
        :raises CoreCommandError: when a non-zero exit status occurs
        """
        logger.debug("mounting source(%s) target(%s)", src_path, target_path)
        raise Exception("not supported")

    def create_file(self, file_path: Path, contents: str, mode: int = 0o644) -> None:
        """
        Create a node file with a given mode.

        :param file_path: name of file to create
        :param contents: contents of file
        :param mode: mode for file
        :return: nothing
        """
        logger.debug("node(%s) create file(%s) mode(%o)", self.name, file_path, mode)
        temp = NamedTemporaryFile(delete=False)
        temp.write(contents.encode())
        temp.close()
        temp_path = Path(temp.name)
        directory = file_path.parent
        if str(directory) != ".":
            self.cmd(f"mkdir -m {0o755:o} -p {directory}")
        if self.server is not None:
            self.server.remote_put(temp_path, temp_path)
        self.host_cmd(f"{DOCKER} cp {temp_path} {self.name}:{file_path}")
        self.cmd(f"chmod {mode:o} {file_path}")
        if self.server is not None:
            self.host_cmd(f"rm -f {temp_path}")
        temp_path.unlink()

    def copy_file(self, src_path: Path, dst_path: Path, mode: int = None) -> None:
        """
        Copy a file to a node, following symlinks and preserving metadata.
        Change file mode if specified.

        :param dst_path: file name to copy file to
        :param src_path: file to copy
        :param mode: mode to copy to
        :return: nothing
        """
        logger.info(
            "node file copy file(%s) source(%s) mode(%o)", dst_path, src_path, mode or 0
        )
        self.cmd(f"mkdir -p {dst_path.parent}")
        if self.server:
            temp = NamedTemporaryFile(delete=False)
            temp_path = Path(temp.name)
            src_path = temp_path
            self.server.remote_put(src_path, temp_path)
        self.host_cmd(f"{DOCKER} cp {src_path} {self.name}:{dst_path}")
        if mode is not None:
            self.cmd(f"chmod {mode:o} {dst_path}")
