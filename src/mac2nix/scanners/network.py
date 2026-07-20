"""Network scanner — discovers network interfaces, DNS, proxies, and Wi-Fi."""

from __future__ import annotations

import logging
import re
import shutil

from mac2nix.models.system import NetworkConfig, NetworkInterface, VpnProfile
from mac2nix.scanners._utils import run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)


@register("network")
class NetworkScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "network"

    def is_available(self) -> bool:
        return shutil.which("networksetup") is not None

    def scan(self) -> NetworkConfig:
        ip_map, ipv6_map, active_map = self._parse_ifconfig()
        interfaces = self._get_interfaces(ip_map, ipv6_map, active_map)
        dns_servers, search_domains = self._get_dns()
        proxy_settings = self._get_proxy_settings(interfaces)
        proxy_bypass_domains = self._get_proxy_bypass_domains(interfaces)
        wifi_networks = self._get_wifi_networks(interfaces)
        vpn_profiles = self._get_vpn_profiles()
        known_network_services = self._get_network_services()
        locations, current_location = self._get_locations()

        return NetworkConfig(
            interfaces=interfaces,
            dns_servers=dns_servers,
            search_domains=search_domains,
            proxy_settings=proxy_settings,
            wifi_networks=wifi_networks,
            vpn_profiles=vpn_profiles,
            proxy_bypass_domains=proxy_bypass_domains,
            known_network_services=known_network_services,
            locations=locations,
            current_location=current_location,
        )

    def _get_interfaces(
        self,
        ip_map: dict[str, str],
        ipv6_map: dict[str, str],
        active_map: dict[str, bool],
    ) -> list[NetworkInterface]:
        """Get all network interfaces in a single subprocess call."""
        result = run_command(["networksetup", "-listallhardwareports"])
        if result is None or result.returncode != 0:
            return []

        interfaces: list[NetworkInterface] = []
        current_port: str | None = None
        current_device: str | None = None

        for raw_line in result.stdout.splitlines():
            stripped = raw_line.strip()
            if stripped.startswith("Hardware Port:"):
                current_port = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("Device:"):
                current_device = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("Ethernet Address:"):
                if current_port:
                    dev = current_device or ""
                    interfaces.append(
                        NetworkInterface(
                            name=current_port,
                            hardware_port=current_port,
                            device=current_device,
                            ip_address=ip_map.get(dev),
                            ipv6_address=ipv6_map.get(dev),
                            is_active=active_map.get(dev),
                        )
                    )
                current_port = None
                current_device = None

        return interfaces

    def _parse_ifconfig(self) -> tuple[dict[str, str], dict[str, str], dict[str, bool]]:
        """Parse ifconfig output for IPv4, IPv6, and active status."""
        result = run_command(["ifconfig"])
        if result is None or result.returncode != 0:
            return {}, {}, {}

        ip_map: dict[str, str] = {}
        ipv6_map: dict[str, str] = {}
        active_map: dict[str, bool] = {}
        current_iface = ""

        for raw_line in result.stdout.splitlines():
            if raw_line and not raw_line[0].isspace() and ":" in raw_line:
                current_iface = raw_line.split(":")[0]
                # Default to False; will be updated by "status:" line
                active_map[current_iface] = False
            elif current_iface:
                stripped = raw_line.strip()
                if stripped.startswith("status:"):
                    # "status: active" means link is up; "status: inactive" means no link
                    status_value = stripped.split(":", 1)[1].strip()
                    active_map[current_iface] = status_value == "active"
                elif "inet " in raw_line:
                    match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", raw_line)
                    if match and match.group(1) != "127.0.0.1":
                        ip_map[current_iface] = match.group(1)
                elif "inet6 " in raw_line:
                    match = re.search(r"inet6\s+(\S+)", raw_line)
                    if match:
                        addr = match.group(1).split("%")[0]
                        # Skip link-local addresses
                        if not addr.startswith("fe80:"):
                            ipv6_map[current_iface] = addr

        return ip_map, ipv6_map, active_map

    def _get_dns(self) -> tuple[list[str], list[str]]:
        result = run_command(["scutil", "--dns"])
        if result is None or result.returncode != 0:
            return [], []

        dns_servers: list[str] = []
        search_domains: list[str] = []

        for raw_line in result.stdout.splitlines():
            stripped = raw_line.strip()
            ns_match = re.match(r"nameserver\[\d+\]\s*:\s*(.+)", stripped)
            if ns_match:
                server = ns_match.group(1).strip()
                if server not in dns_servers:
                    dns_servers.append(server)
                continue
            sd_match = re.match(r"search domain\[\d+\]\s*:\s*(.+)", stripped)
            if sd_match:
                domain = sd_match.group(1).strip()
                if domain not in search_domains:
                    search_domains.append(domain)

        return dns_servers, search_domains

    def _get_proxy_settings(self, interfaces: list[NetworkInterface]) -> dict[str, str]:
        proxy: dict[str, str] = {}
        service = self._get_proxy_service(interfaces)

        for proxy_type, flag in [
            ("http", "-getwebproxy"),
            ("https", "-getsecurewebproxy"),
            ("socks", "-getsocksfirewallproxy"),
            ("ftp", "-getftpproxy"),
        ]:
            result = run_command(["networksetup", flag, service])
            if result is None or result.returncode != 0:
                continue
            enabled = False
            server = ""
            port = ""
            for line in result.stdout.splitlines():
                if line.startswith("Enabled:"):
                    enabled = line.split(":", 1)[1].strip().lower() == "yes"
                elif line.startswith("Server:"):
                    server = line.split(":", 1)[1].strip()
                elif line.startswith("Port:"):
                    port = line.split(":", 1)[1].strip()
            if enabled and server:
                proxy[f"{proxy_type}_proxy"] = f"{server}:{port}" if port else server

        return proxy

    def _get_proxy_bypass_domains(self, interfaces: list[NetworkInterface]) -> list[str]:
        """Get proxy bypass domains."""
        service = self._get_proxy_service(interfaces)
        result = run_command(["networksetup", "-getproxybypassdomains", service])
        if result is None or result.returncode != 0:
            return []
        domains = []
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("There"):
                domains.append(stripped)
        return domains

    @staticmethod
    def _get_proxy_service(interfaces: list[NetworkInterface]) -> str:
        """Determine which network service to query for proxy settings."""
        if any(i.name == "Wi-Fi" for i in interfaces):
            return "Wi-Fi"
        if interfaces:
            return interfaces[0].name
        return "Wi-Fi"

    def _get_wifi_networks(self, interfaces: list[NetworkInterface]) -> list[str]:
        """Get all saved WiFi networks."""
        wifi_device = None
        for iface in interfaces:
            if iface.name == "Wi-Fi" and iface.device:
                wifi_device = iface.device
                break
        if wifi_device is None:
            wifi_device = "en0"

        # Try preferred networks list first (gets all saved networks)
        result = run_command(["networksetup", "-listpreferredwirelessnetworks", wifi_device])
        if result is not None and result.returncode == 0:
            networks = []
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("Preferred networks"):
                    continue
                if stripped:
                    networks.append(stripped)
            if networks:
                return networks

        # Fallback to current network only
        result = run_command(["networksetup", "-getairportnetwork", wifi_device])
        if result is not None and result.returncode == 0:
            output = result.stdout.strip()
            if "Current Wi-Fi Network:" in output:
                network = output.split(":", 1)[1].strip()
                if network:
                    return [network]

        return []

    def _get_vpn_profiles(self) -> list[VpnProfile]:
        """Get VPN profiles from scutil --nc list."""
        result = run_command(["scutil", "--nc", "list"])
        if result is None or result.returncode != 0:
            return []

        profiles: list[VpnProfile] = []
        # Lines like:
        #   * (Disconnected)  UUID VPN (com.ubnt.wifiman) "Name"  [VPN:com.ubnt.wifiman]
        #   * (Connected)     UUID PPP --> DeviceName "Name"      [PPP:Modem]
        vpn_pattern = re.compile(r'^\*\s+\((\w+)\)\s+\S+\s+.*?"([^"]+)"\s+\[([^\]]+)\]')
        for line in result.stdout.splitlines():
            match = vpn_pattern.match(line.strip())
            if match:
                protocol = match.group(3).split(":")[0]  # "VPN:com.foo" → "VPN"
                profiles.append(
                    VpnProfile(
                        name=match.group(2),
                        status=match.group(1),
                        protocol=protocol,
                    )
                )
        return profiles

    def _get_network_services(self) -> list[str]:
        """Get all network service names for networking.knownNetworkServices."""
        result = run_command(["networksetup", "-listallnetworkservices"])
        if result is None or result.returncode != 0:
            return []
        services: list[str] = []
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("An asterisk"):
                continue
            if stripped.startswith("*"):
                stripped = stripped.removeprefix("*").strip()
            if stripped:
                services.append(stripped)
        return services

    def _get_locations(self) -> tuple[list[str], str | None]:
        """Get network locations and current location."""
        locations: list[str] = []
        result = run_command(["networksetup", "-listlocations"])
        if result is not None and result.returncode == 0:
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped:
                    locations.append(stripped)

        current_location: str | None = None
        result = run_command(["networksetup", "-getcurrentlocation"])
        if result is not None and result.returncode == 0:
            loc = result.stdout.strip()
            if loc:
                current_location = loc

        return locations, current_location
