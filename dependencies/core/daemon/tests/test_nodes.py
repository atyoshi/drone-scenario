import json
from unittest import mock
from pathlib import Path

import pytest
import yaml

from core.emulator.data import InterfaceData
from core.emulator.session import Session
from core.errors import CoreCommandError, CoreError
from core.nodes.base import CoreNode
from core.nodes.docker import DockerNode, DockerOptions
from core.nodes.network import HubNode, SwitchNode, WlanNode
from core.nodes.podman import PodmanNode, PodmanOptions

MODELS = ["router", "host", "PC", "mdr"]
NET_TYPES = [SwitchNode, HubNode, WlanNode]


class TestNodes:
    @pytest.mark.parametrize("model", MODELS)
    def test_node_add(self, session: Session, model: str):
        # given
        options = CoreNode.create_options()
        options.model = model

        # when
        node = session.add_node(CoreNode, options=options)

        # then
        assert node
        assert node.alive()
        assert node.up

    def test_node_set_pos(self, session: Session):
        # given
        node = session.add_node(CoreNode)
        x, y = 100.0, 50.0

        # when
        session.set_node_pos(node, x, y)

        # then
        assert node.position.x == x
        assert node.position.y == y

    def test_node_set_geo(self, session: Session):
        # given
        node = session.add_node(CoreNode)
        lon, lat, alt = 0.0, 0.0, 0.0

        # when
        session.set_node_geo(node, lon, lat, alt)

        # then
        assert node.position.lon == lon
        assert node.position.lat == lat
        assert node.position.alt == alt

    def test_node_delete(self, session: Session):
        # given
        node = session.add_node(CoreNode)

        # when
        session.delete_node(node.id)

        # then
        with pytest.raises(CoreError):
            session.get_node(node.id, CoreNode)

    def test_node_add_iface(self, session: Session):
        # given
        node = session.add_node(CoreNode)

        # when
        iface = node.create_iface()

        # then
        assert iface.id in node.ifaces

    def test_node_get_iface(self, session: Session):
        # given
        node = session.add_node(CoreNode)
        iface = node.create_iface()
        assert iface.id in node.ifaces

        # when
        iface2 = node.get_iface(iface.id)

        # then
        assert iface == iface2

    def test_node_delete_iface(self, session: Session):
        # given
        node = session.add_node(CoreNode)
        iface = node.create_iface()
        assert iface.id in node.ifaces

        # when
        node.delete_iface(iface.id)

        # then
        assert iface.id not in node.ifaces

    @pytest.mark.parametrize(
        "mac,expected",
        [
            ("AA-AA-AA-FF-FF-FF", "aa:aa:aa:ff:ff:ff"),
            ("00:00:00:FF:FF:FF", "00:00:00:ff:ff:ff"),
        ],
    )
    def test_node_set_mac(self, session: Session, mac: str, expected: str):
        # given
        node = session.add_node(CoreNode)
        iface_data = InterfaceData()
        iface = node.create_iface(iface_data)

        # when
        iface.set_mac(mac)

        # then
        assert str(iface.mac) == expected

    @pytest.mark.parametrize(
        "mac", ["AAA:AA:AA:FF:FF:FF", "AA:AA:AA:FF:FF", "AA/AA/AA/FF/FF/FF"]
    )
    def test_node_set_mac_exception(self, session: Session, mac: str):
        # given
        node = session.add_node(CoreNode)
        iface_data = InterfaceData()
        iface = node.create_iface(iface_data)

        # when
        with pytest.raises(CoreError):
            iface.set_mac(mac)

    @pytest.mark.parametrize(
        "ip,expected,is_ip6",
        [
            ("127", "127.0.0.0/32", False),
            ("10.0.0.1/24", "10.0.0.1/24", False),
            ("2001::", "2001::/128", True),
            ("2001::/64", "2001::/64", True),
        ],
    )
    def test_node_add_ip(self, session: Session, ip: str, expected: str, is_ip6: bool):
        # given
        node = session.add_node(CoreNode)
        iface_data = InterfaceData()
        iface = node.create_iface(iface_data)

        # when
        iface.add_ip(ip)

        # then
        if is_ip6:
            assert str(iface.get_ip6()) == expected
        else:
            assert str(iface.get_ip4()) == expected

    def test_node_add_ip_exception(self, session):
        # given
        node = session.add_node(CoreNode)
        iface_data = InterfaceData()
        iface = node.create_iface(iface_data)
        ip = "256.168.0.1/24"

        # when
        with pytest.raises(CoreError):
            iface.add_ip(ip)

    @pytest.mark.parametrize("net_type", NET_TYPES)
    def test_net(self, session, net_type):
        # given

        # when
        node = session.add_node(net_type)

        # then
        assert node
        assert node.up

    def test_ptp(self, session):
        # given

        # when
        ptp = session.create_ptp()

        # then
        assert ptp
        assert ptp.up

    def test_control_net(self, session):
        # given

        # when
        control_net = session.create_control_net(0, "172.168.0.0/24", None, None)

        # then
        assert control_net
        assert control_net.up

    def test_control_net_error(self, session):
        # given
        ip_prefix = "172.168.0.0/24"
        session.create_control_net(0, ip_prefix, None, None)

        # when
        with pytest.raises(CoreError):
            session.create_control_net(0, ip_prefix, None, None)

    def test_container_options_defaults(self):
        # given
        docker_options = DockerOptions()
        podman_options = PodmanOptions()

        # then
        assert not docker_options.image_compatibility
        assert not podman_options.image_compatibility
        assert docker_options.model == "PC"
        assert podman_options.model == "PC"
        assert docker_options.services == ["DefaultRoute"]
        assert podman_options.services == ["DefaultRoute"]

    def test_docker_image_compatibility_builds_derived_image(self):
        # given
        node = DockerNode.__new__(DockerNode)
        node.name = "n1"
        node.id = 1
        node.image = "ubuntu:latest"
        node.directory = Path("/tmp/n1.conf")
        node.session = mock.MagicMock(id=1000)
        node._write_host_file = mock.MagicMock()
        node._compatibility_dockerfile = mock.MagicMock(return_value="FROM ubuntu\n")
        node.host_cmd = mock.MagicMock()

        # when
        node.setup_image_compatibility()

        # then
        assert node.image == "core-compat-1000-1-n1:latest"
        node._write_host_file.assert_called_once_with(
            Path("/tmp/n1.conf/Dockerfile.corecompat"), "FROM ubuntu\n"
        )
        node.host_cmd.assert_called_once_with(
            "docker build --network host -t core-compat-1000-1-n1:latest "
            "-f Dockerfile.corecompat .",
            cwd=Path("/tmp/n1.conf"),
        )

    def test_docker_image_compatibility_uses_exec_form_run(self):
        # given
        node = DockerNode.__new__(DockerNode)
        node.name = "n1"
        node._image_user = mock.MagicMock(return_value=None)

        # when
        dockerfile = node._compatibility_dockerfile("example:latest")

        # then
        run = dockerfile.splitlines()[2].replace("RUN ", "", 1)
        assert json.loads(run)[:2] == ["/bin/sh", "-euxc"]
        assert "SHELL [\"/bin/sh\", \"-c\"]" not in dockerfile

    @pytest.mark.parametrize("node_type", [DockerNode, PodmanNode])
    def test_image_compatibility_repairs_archived_apt_sources(self, node_type):
        # given
        node = node_type.__new__(node_type)
        node.name = "n1"
        node._image_user = mock.MagicMock(return_value=None)

        # when
        dockerfile = node._compatibility_dockerfile("example:latest")

        # then
        assert "Acquire::Check-Valid-Until=false" in dockerfile
        assert "if ! apt_update; then apt_fix_sources; apt_update; fi" in dockerfile
        assert "archive.debian.org/debian" in dockerfile
        assert "old-releases.ubuntu.com/ubuntu" in dockerfile
        assert "archive\\.debian\\.org\\/debian [^[:space:]]*-updates" in dockerfile
        assert "done; };" in dockerfile
        assert "apt-get install -y --allow-unauthenticated --force-yes" in dockerfile

    def test_docker_prepare_compose_project_local(self):
        # given
        node = DockerNode.__new__(DockerNode)
        node.directory = Path("/tmp/n1.conf")
        node.server = None
        node._write_host_file = mock.MagicMock()

        with mock.patch("core.nodes.docker.shutil.copytree") as copytree:
            # when
            compose_path = node._prepare_compose_project(
                "/tmp/project/docker-compose.yml", "services:\n"
            )

        # then
        assert compose_path == Path("/tmp/n1.conf/docker-compose.yml")
        copytree.assert_called_once_with(
            Path("/tmp/project"),
            Path("/tmp/n1.conf"),
            dirs_exist_ok=True,
            symlinks=True,
        )
        node._write_host_file.assert_called_once_with(
            Path("/tmp/n1.conf/docker-compose.yml"), "services:\n"
        )

    def test_docker_prepare_compose_project_remote(self):
        # given
        node = DockerNode.__new__(DockerNode)
        node.directory = Path("/tmp/n1.conf")
        node.server = mock.MagicMock()
        node.host_cmd = mock.MagicMock()
        node._write_host_file = mock.MagicMock()

        # when
        compose_path = node._prepare_compose_project(
            "/tmp/project/docker-compose.yml", "services:\n"
        )

        # then
        assert compose_path == Path("/tmp/n1.conf/docker-compose.yml")
        node.host_cmd.assert_called_once_with(
            'src_dir=$(cd /tmp/project && pwd -P) && dst_dir=$(cd /tmp/n1.conf && pwd -P) && if [ "$src_dir" != "$dst_dir" ]; then cp -a "$src_dir"/. "$dst_dir"/; fi',
            shell=True,
        )
        node._write_host_file.assert_called_once_with(
            Path("/tmp/n1.conf/docker-compose.yml"), "services:\n"
        )

    def test_docker_resolve_shell_falls_back_when_image_has_no_bash(self):
        # A Docker node runs whatever image the scenario names, and Alpine,
        # busybox and distroless images ship only /bin/sh. Hardcoding bash made
        # every shell=True service command fail on those with
        # 'exec: "bash": no such file or directory'. Service startup failures
        # do not stop a node coming up, so the node looked healthy while
        # running none of its services.
        def node_with(available):
            node = DockerNode.__new__(DockerNode)
            node.name = "docker-7"
            node.runtime_container = "docker-7"
            node.shell = "bash"
            node.host_cmd = mock.MagicMock(
                side_effect=lambda cmd, **kwargs: (
                    ""
                    if cmd.split()[3] in available
                    else _raise(CoreCommandError(1, cmd, "", "not found"))
                )
            )
            return node

        def _raise(exc):
            raise exc

        # bash is preferred where present, so bash-specific templates still work
        assert node_with({"bash", "sh"})._resolve_shell() == "bash"
        # the regression: sh-only images must fall back rather than fail
        assert node_with({"sh"})._resolve_shell() == "sh"
        # neither available keeps bash so the recognizable error still surfaces
        assert node_with(set())._resolve_shell() == "bash"

        # the resolved shell is what create_cmd actually uses
        node = node_with({"sh"})
        node.shell = node._resolve_shell()
        assert node.create_cmd("echo hi", shell=True) == (
            "docker exec docker-7 sh -c 'echo hi'"
        )
        # non-shell commands are untouched
        assert node.create_cmd("echo hi", shell=False) == "docker exec docker-7 echo hi"

    def test_docker_parse_environ_skips_entries_without_a_separator(self):
        # /proc/<pid>/environ is ordinary process memory, and a process may
        # overwrite it. nginx rewrites it to hold its process title, so the
        # region reads back as title text plus NUL padding and contains no
        # KEY=VALUE pairs. Splitting on "=" unconditionally raises ValueError
        # there, and because this runs in the session's startup threadpool it
        # strands the whole session in configuration state.
        # given
        nginx_environ = " nginx -g daemon off;" + "\x00" * 226

        # when / then
        assert DockerNode._parse_environ(nginx_environ) == {}

        # real environments still parse, including values containing "="
        assert DockerNode._parse_environ(
            "PATH=/usr/bin\x00HOSTNAME=docker-7\x00ARGS=a=b\x00"
        ) == {"PATH": "/usr/bin", "HOSTNAME": "docker-7", "ARGS": "a=b"}

        # junk interleaved with real pairs keeps the pairs
        assert DockerNode._parse_environ(
            "PATH=/usr/bin\x00nginx: master process\x00LANG=C\x00"
        ) == {"PATH": "/usr/bin", "LANG": "C"}

        # degenerate inputs must not raise
        for value in ("", "\x00\x00", "=novalue\x00", "noequals"):
            DockerNode._parse_environ(value)

    def test_docker_compose_args_use_default_project_name(self):
        # An explicit --project-name must NOT be passed: compose derives the
        # project from the node directory it runs in (<node>.conf), and
        # tooling that pre-creates this node's container or named volumes
        # targets that same default. Forcing a per-node project name instead
        # makes compose treat those as another project's resources -- the
        # container name conflicts, and project-scoped named volumes silently
        # resolve to new empty ones, losing pre-populated contents.
        # given
        node = DockerNode.__new__(DockerNode)
        node.name = "web_node"
        node.id = 1
        node.session = mock.MagicMock(id=1000)
        node.compose_files = ["compose.yaml", "docker-compose.corecompat.yml"]

        # when
        args = node._compose_args()

        # then
        assert args == "-f compose.yaml -f docker-compose.corecompat.yml"
        assert "--project-name" not in args

    def test_docker_compose_uses_core_network_only(self):
        # given
        node = DockerNode.__new__(DockerNode)
        node.compose_name = "web"
        rendered = """
services:
  web:
    image: example/web
    depends_on:
      - mongo
    ports:
      - \"8081:8081\"
    networks:
      - default
    extra_hosts:
      - existing:192.0.2.1
  mongo:
    image: mongo:3.4
    ports:
      - \"27017:27017\"
    networks:
      - default
"""

        # when
        data = yaml.safe_load(node._compose_core_network(rendered))

        # then
        web = data["services"]["web"]
        mongo = data["services"]["mongo"]
        assert web["network_mode"] == "none"
        assert "depends_on" not in web
        assert "networks" not in web
        assert "ports" not in web
        assert web["extra_hosts"] == {
            "existing": "192.0.2.1",
            "mongo": "127.0.0.1",
        }
        assert mongo["network_mode"] == "service:web"
        assert "networks" not in mongo
        assert "ports" not in mongo
        assert "extra_hosts" not in mongo

    def test_docker_volume_mountpoint_strips_command_newline(self):
        # given
        node = DockerNode.__new__(DockerNode)
        node.host_cmd = mock.MagicMock(
            return_value="/var/lib/docker/volumes/data/_data\n"
        )
        volume = mock.MagicMock(src="data")

        # when
        mountpoint = node._volume_mountpoint(volume)

        # then
        assert mountpoint == "/var/lib/docker/volumes/data/_data"
        node.host_cmd.assert_called_once_with(
            "docker volume inspect -f '{{.Mountpoint}}' data"
        )

    @mock.patch("core.nodes.docker.utils.cmd")
    def test_docker_container_exists(self, cmd):
        # given
        cmd.return_value = "1f3d5b7a\n"

        # when
        exists = DockerNode.container_exists("n1")

        # then
        assert exists
        cmd.assert_called_once_with(
            "docker container ls -aq --filter 'name=^/n1$'"
        )

    @mock.patch("core.nodes.docker.utils.cmd")
    def test_docker_remove_container(self, cmd):
        # when
        DockerNode.remove_container("n1")

        # then
        cmd.assert_called_once_with("docker rm -f n1")

    def test_docker_compatibility_image_name(self):
        assert (
            DockerNode.compatibility_image_name(1000, 1, "Web Node")
            == "core-compat-1000-1-web-node:latest"
        )

    @mock.patch("core.nodes.docker.utils.cmd")
    def test_docker_image_exists(self, cmd):
        # given
        cmd.return_value = "1f3d5b7a\n"

        # when
        exists = DockerNode.image_exists("core-compat-1-1-n1:latest")

        # then
        assert exists
        cmd.assert_called_once_with("docker image ls -q core-compat-1-1-n1:latest")

    @mock.patch("core.nodes.docker.utils.cmd")
    def test_docker_remove_image(self, cmd):
        # when
        DockerNode.remove_image("core-compat-1-1-n1:latest")

        # then
        cmd.assert_called_once_with("docker image rm -f core-compat-1-1-n1:latest")

    def test_docker_compose_image_compatibility_override(self):
        # given
        node = DockerNode.__new__(DockerNode)
        node.name = "n1"
        node.id = 1
        node.compose_name = "web"
        node.directory = Path("/tmp/n1.conf")
        node.session = mock.MagicMock(id=1000)
        node._write_host_file = mock.MagicMock()
        node._compatibility_dockerfile = mock.MagicMock(return_value="FROM app\n")
        rendered = "services:\n  web:\n    image: vulhub/spring-boot-jetty:3.2.4\n"

        # when
        override_path = node._compose_image_compatibility_override(rendered)

        # then
        assert override_path == Path("/tmp/n1.conf/docker-compose.corecompat.yml")
        assert node._write_host_file.call_count == 2
        _, override = node._write_host_file.call_args_list[1].args
        assert "core-compat-1000-1-n1:latest" in override
        assert "Dockerfile.corecompat" in override
        assert "network: host" in override

    def test_docker_compose_reuses_existing_compatibility_image(self):
        # given
        node = DockerNode.__new__(DockerNode)
        node.name = "n1"
        node.id = 1
        node.compose_name = "web"
        node.directory = Path("/tmp/n1.conf")
        node.session = mock.MagicMock(id=1000)
        node.session.reuse_compatibility_images = {
            "core-compat-1000-1-n1:latest"
        }
        node._write_host_file = mock.MagicMock()
        rendered = "services:\n  web:\n    image: example/web\n"

        # when
        override_path = node._compose_image_compatibility_override(rendered)

        # then
        assert override_path == Path("/tmp/n1.conf/docker-compose.corecompat.yml")
        node._write_host_file.assert_called_once()
        _, override = node._write_host_file.call_args.args
        assert "core-compat-1000-1-n1:latest" in override
        assert "build:" not in override

    def test_docker_compose_checks_image_compatibility(self):
        # given
        node = DockerNode.__new__(DockerNode)
        node.image_compatibility = True
        node.compose = "/tmp/docker-compose.yml"

        # when
        result = node.should_check_image_compatibility()

        # then
        assert result
