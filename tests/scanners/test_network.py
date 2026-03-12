"""Tests for network scanner."""

from unittest.mock import patch

from mac2nix.models.system import NetworkConfig
from mac2nix.scanners.network import NetworkScanner

_HARDWARE_PORTS = """\
Hardware Port: Wi-Fi
Device: en0
Ethernet Address: aa:bb:cc:dd:ee:ff

Hardware Port: Thunderbolt Ethernet
Device: en1
Ethernet Address: ff:ee:dd:cc:bb:aa
"""

_IFCONFIG = """\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.42 netmask 0xffffff00 broadcast 192.168.1.255
en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 10.0.0.5 netmask 0xffffff00 broadcast 10.0.0.255
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
"""

_DNS_OUTPUT = """\
resolver #1
  nameserver[0] : 8.8.8.8
  nameserver[1] : 8.8.4.4
  search domain[0] : home.local
"""

_PROXY_DISABLED = """\
Enabled: No
Server:
Port: 0
"""

_PROXY_ENABLED = """\
Enabled: Yes
Server: proxy.corp.com
Port: 8080
"""

_WIFI_NETWORK = "Current Wi-Fi Network: HomeNetwork"


def _network_side_effect(responses):
    """Create a side_effect function that dispatches by command binary and flag."""

    def side_effect(cmd, **_kwargs):
        binary = cmd[0]
        if binary == "networksetup":
            flag = cmd[1] if len(cmd) > 1 else ""
            return responses.get(("networksetup", flag))
        if binary == "ifconfig":
            return responses.get(("ifconfig",))
        if binary == "scutil":
            # Distinguish scutil --dns from scutil --nc list
            flag = cmd[1] if len(cmd) > 1 else ""
            sub = cmd[2] if len(cmd) > 2 else ""
            return responses.get(("scutil", flag, sub), responses.get(("scutil",)))
        return None

    return side_effect


class TestNetworkScanner:
    def test_name_property(self) -> None:
        assert NetworkScanner().name == "network"

    def test_is_available_present(self) -> None:
        with patch("mac2nix.scanners.network.shutil.which", return_value="/usr/sbin/networksetup"):
            assert NetworkScanner().is_available() is True

    def test_is_available_absent(self) -> None:
        with patch("mac2nix.scanners.network.shutil.which", return_value=None):
            assert NetworkScanner().is_available() is False

    def test_parses_interfaces(self, cmd_result) -> None:
        responses = {
            ("networksetup", "-listallhardwareports"): cmd_result(_HARDWARE_PORTS),
            ("ifconfig",): cmd_result(_IFCONFIG),
            ("scutil",): cmd_result(_DNS_OUTPUT),
            ("networksetup", "-getwebproxy"): cmd_result(_PROXY_DISABLED),
            ("networksetup", "-getsecurewebproxy"): cmd_result(_PROXY_DISABLED),
            ("networksetup", "-getairportnetwork"): cmd_result(_WIFI_NETWORK),
        }

        with patch(
            "mac2nix.scanners.network.run_command",
            side_effect=_network_side_effect(responses),
        ):
            result = NetworkScanner().scan()

        assert isinstance(result, NetworkConfig)
        assert len(result.interfaces) == 2
        wifi = next(i for i in result.interfaces if i.name == "Wi-Fi")
        assert wifi.ip_address == "192.168.1.42"
        assert wifi.device == "en0"
        thunder = next(i for i in result.interfaces if i.name == "Thunderbolt Ethernet")
        assert thunder.ip_address == "10.0.0.5"
        assert thunder.device == "en1"

    def test_parses_dns(self, cmd_result) -> None:
        responses = {
            ("networksetup", "-listallhardwareports"): cmd_result(_HARDWARE_PORTS),
            ("ifconfig",): cmd_result(_IFCONFIG),
            ("scutil",): cmd_result(_DNS_OUTPUT),
            ("networksetup", "-getwebproxy"): cmd_result(_PROXY_DISABLED),
            ("networksetup", "-getsecurewebproxy"): cmd_result(_PROXY_DISABLED),
            ("networksetup", "-getairportnetwork"): cmd_result(""),
        }

        with patch(
            "mac2nix.scanners.network.run_command",
            side_effect=_network_side_effect(responses),
        ):
            result = NetworkScanner().scan()

        assert isinstance(result, NetworkConfig)
        assert "8.8.8.8" in result.dns_servers
        assert "8.8.4.4" in result.dns_servers
        assert "home.local" in result.search_domains

    def test_wifi_detection(self, cmd_result) -> None:
        responses = {
            ("networksetup", "-listallhardwareports"): cmd_result(
                "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n"
            ),
            ("ifconfig",): cmd_result("en0: flags=8863\n\tinet 10.0.0.1 netmask 0xffffff00\n"),
            ("scutil",): cmd_result(""),
            ("networksetup", "-getwebproxy"): cmd_result(_PROXY_DISABLED),
            ("networksetup", "-getsecurewebproxy"): cmd_result(_PROXY_DISABLED),
            ("networksetup", "-getairportnetwork"): cmd_result("Current Wi-Fi Network: CoffeeShop"),
        }

        with patch(
            "mac2nix.scanners.network.run_command",
            side_effect=_network_side_effect(responses),
        ):
            result = NetworkScanner().scan()

        assert isinstance(result, NetworkConfig)
        assert "CoffeeShop" in result.wifi_networks

    def test_networksetup_fails(self) -> None:
        with patch("mac2nix.scanners.network.run_command", return_value=None):
            result = NetworkScanner().scan()

        assert isinstance(result, NetworkConfig)
        assert result.interfaces == []
        assert result.dns_servers == []

    def test_returns_network_config(self) -> None:
        with patch("mac2nix.scanners.network.run_command", return_value=None):
            result = NetworkScanner().scan()

        assert isinstance(result, NetworkConfig)

    def test_proxy_enabled(self, cmd_result) -> None:
        responses = {
            ("networksetup", "-listallhardwareports"): cmd_result(
                "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n"
            ),
            ("ifconfig",): cmd_result("en0: flags=8863\n\tinet 10.0.0.1 netmask 0xffffff00\n"),
            ("scutil",): cmd_result(""),
            ("networksetup", "-getwebproxy"): cmd_result(_PROXY_ENABLED),
            ("networksetup", "-getsecurewebproxy"): cmd_result(_PROXY_DISABLED),
            ("networksetup", "-getairportnetwork"): cmd_result(""),
        }

        with patch(
            "mac2nix.scanners.network.run_command",
            side_effect=_network_side_effect(responses),
        ):
            result = NetworkScanner().scan()

        assert isinstance(result, NetworkConfig)
        assert "http_proxy" in result.proxy_settings
        assert result.proxy_settings["http_proxy"] == "proxy.corp.com:8080"
        assert "https_proxy" not in result.proxy_settings

    def test_ipv6_address(self, cmd_result) -> None:
        ifconfig_ipv6 = (
            "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
            "\tinet 192.168.1.42 netmask 0xffffff00 broadcast 192.168.1.255\n"
            "\tinet6 2001:db8::1 prefixlen 64\n"
        )
        responses = {
            ("networksetup", "-listallhardwareports"): cmd_result(
                "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n"
            ),
            ("ifconfig",): cmd_result(ifconfig_ipv6),
            ("scutil",): cmd_result(""),
        }

        with patch(
            "mac2nix.scanners.network.run_command",
            side_effect=_network_side_effect(responses),
        ):
            result = NetworkScanner().scan()

        assert isinstance(result, NetworkConfig)
        wifi = next(i for i in result.interfaces if i.name == "Wi-Fi")
        assert wifi.ipv6_address == "2001:db8::1"

    def test_ipv6_link_local_skipped(self, cmd_result) -> None:
        ifconfig_link_local = (
            "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
            "\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x4\n"
        )
        responses = {
            ("networksetup", "-listallhardwareports"): cmd_result(
                "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n"
            ),
            ("ifconfig",): cmd_result(ifconfig_link_local),
            ("scutil",): cmd_result(""),
        }

        with patch(
            "mac2nix.scanners.network.run_command",
            side_effect=_network_side_effect(responses),
        ):
            result = NetworkScanner().scan()

        assert isinstance(result, NetworkConfig)
        wifi = next(i for i in result.interfaces if i.name == "Wi-Fi")
        assert wifi.ipv6_address is None

    def test_interface_active_status(self, cmd_result) -> None:
        ifconfig_mixed = (
            "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
            "\tinet 192.168.1.42 netmask 0xffffff00\n"
            "\tstatus: active\n"
            "en1: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500\n"
            "\tstatus: inactive\n"
        )
        responses = {
            ("networksetup", "-listallhardwareports"): cmd_result(_HARDWARE_PORTS),
            ("ifconfig",): cmd_result(ifconfig_mixed),
            ("scutil",): cmd_result(""),
        }

        with patch(
            "mac2nix.scanners.network.run_command",
            side_effect=_network_side_effect(responses),
        ):
            result = NetworkScanner().scan()

        assert isinstance(result, NetworkConfig)
        wifi = next(i for i in result.interfaces if i.name == "Wi-Fi")
        assert wifi.is_active is True
        thunder = next(i for i in result.interfaces if i.name == "Thunderbolt Ethernet")
        assert thunder.is_active is False

    def test_vpn_profiles(self, cmd_result) -> None:
        vpn_output = (
            '* (Connected)     ABC12345-1234-1234-1234-123456789012 "Work VPN"                   [IPSec]\n'
            '* (Disconnected)  DEF12345-1234-1234-1234-123456789012 "Home VPN"                   [L2TP]\n'
        )
        responses = {
            ("networksetup", "-listallhardwareports"): cmd_result(
                "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n"
            ),
            ("ifconfig",): cmd_result("en0: flags=8863<UP>\n\tinet 10.0.0.1 netmask 0xffffff00\n"),
            ("scutil",): cmd_result(""),
            ("scutil", "--nc", "list"): cmd_result(vpn_output),
        }

        with patch(
            "mac2nix.scanners.network.run_command",
            side_effect=_network_side_effect(responses),
        ):
            result = NetworkScanner().scan()

        assert isinstance(result, NetworkConfig)
        assert len(result.vpn_profiles) == 2
        work_vpn = next(v for v in result.vpn_profiles if v.name == "Work VPN")
        assert work_vpn.status == "Connected"
        assert work_vpn.protocol == "IPSec"
        home_vpn = next(v for v in result.vpn_profiles if v.name == "Home VPN")
        assert home_vpn.status == "Disconnected"
        assert home_vpn.protocol == "L2TP"

    def test_proxy_bypass_domains(self, cmd_result) -> None:
        bypass_output = "*.local\n169.254/16\nlocalhost\n"
        responses = {
            ("networksetup", "-listallhardwareports"): cmd_result(
                "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n"
            ),
            ("ifconfig",): cmd_result("en0: flags=8863<UP>\n\tinet 10.0.0.1 netmask 0xffffff00\n"),
            ("scutil",): cmd_result(""),
            ("networksetup", "-getproxybypassdomains"): cmd_result(bypass_output),
        }

        with patch(
            "mac2nix.scanners.network.run_command",
            side_effect=_network_side_effect(responses),
        ):
            result = NetworkScanner().scan()

        assert isinstance(result, NetworkConfig)
        assert "*.local" in result.proxy_bypass_domains
        assert "localhost" in result.proxy_bypass_domains

    def test_socks_proxy(self, cmd_result) -> None:
        socks_enabled = "Enabled: Yes\nServer: socks.corp.com\nPort: 1080\n"
        responses = {
            ("networksetup", "-listallhardwareports"): cmd_result(
                "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n"
            ),
            ("ifconfig",): cmd_result("en0: flags=8863<UP>\n\tinet 10.0.0.1 netmask 0xffffff00\n"),
            ("scutil",): cmd_result(""),
            ("networksetup", "-getsocksfirewallproxy"): cmd_result(socks_enabled),
        }

        with patch(
            "mac2nix.scanners.network.run_command",
            side_effect=_network_side_effect(responses),
        ):
            result = NetworkScanner().scan()

        assert isinstance(result, NetworkConfig)
        assert "socks_proxy" in result.proxy_settings
        assert result.proxy_settings["socks_proxy"] == "socks.corp.com:1080"

    def test_network_locations(self, cmd_result) -> None:
        locations_output = "Automatic\nWork\nHome\n"
        current_loc = "Work\n"
        responses = {
            ("networksetup", "-listallhardwareports"): cmd_result(
                "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n"
            ),
            ("ifconfig",): cmd_result("en0: flags=8863<UP>\n\tinet 10.0.0.1 netmask 0xffffff00\n"),
            ("scutil",): cmd_result(""),
            ("networksetup", "-listlocations"): cmd_result(locations_output),
            ("networksetup", "-getcurrentlocation"): cmd_result(current_loc),
        }

        with patch(
            "mac2nix.scanners.network.run_command",
            side_effect=_network_side_effect(responses),
        ):
            result = NetworkScanner().scan()

        assert isinstance(result, NetworkConfig)
        assert result.locations == ["Automatic", "Work", "Home"]
        assert result.current_location == "Work"

    def test_wifi_preferred_networks(self, cmd_result) -> None:
        preferred = "Preferred networks on en0:\n\tHomeNetwork\n\tOfficeWifi\n\tCoffeeShop\n"
        responses = {
            ("networksetup", "-listallhardwareports"): cmd_result(
                "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n"
            ),
            ("ifconfig",): cmd_result("en0: flags=8863<UP>\n\tinet 10.0.0.1 netmask 0xffffff00\n"),
            ("scutil",): cmd_result(""),
            ("networksetup", "-listpreferredwirelessnetworks"): cmd_result(preferred),
        }

        with patch(
            "mac2nix.scanners.network.run_command",
            side_effect=_network_side_effect(responses),
        ):
            result = NetworkScanner().scan()

        assert isinstance(result, NetworkConfig)
        assert len(result.wifi_networks) == 3
        assert "HomeNetwork" in result.wifi_networks
        assert "OfficeWifi" in result.wifi_networks

    def test_empty_ifconfig(self, cmd_result) -> None:
        responses = {
            ("networksetup", "-listallhardwareports"): cmd_result(_HARDWARE_PORTS),
            ("ifconfig",): cmd_result(""),
            ("scutil",): cmd_result(""),
        }

        with patch(
            "mac2nix.scanners.network.run_command",
            side_effect=_network_side_effect(responses),
        ):
            result = NetworkScanner().scan()

        assert isinstance(result, NetworkConfig)
        for iface in result.interfaces:
            assert iface.ip_address is None

    def test_wifi_preferred_fails_falls_back_to_current(self, cmd_result) -> None:
        responses = {
            ("networksetup", "-listallhardwareports"): cmd_result(
                "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n"
            ),
            ("ifconfig",): cmd_result("en0: flags=8863<UP>\n\tinet 10.0.0.1 netmask 0xffffff00\n"),
            ("scutil",): cmd_result(""),
            ("networksetup", "-listpreferredwirelessnetworks"): None,
            ("networksetup", "-getairportnetwork"): cmd_result("Current Wi-Fi Network: FallbackNet"),
        }

        with patch(
            "mac2nix.scanners.network.run_command",
            side_effect=_network_side_effect(responses),
        ):
            result = NetworkScanner().scan()

        assert isinstance(result, NetworkConfig)
        assert result.wifi_networks == ["FallbackNet"]
