"""Network scanner — discovers network interfaces, DNS, proxies, and Wi-Fi."""

from __future__ import annotations

import logging
import re
import shutil

from mac2nix.models.system import NetworkConfig, NetworkInterface
from mac2nix.scanners._utils import run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)


@register
class NetworkScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "network"

    def is_available(self) -> bool:
        return shutil.which("networksetup") is not None

    def scan(self) -> NetworkConfig:
        interfaces = self._get_interfaces()
        dns_servers, search_domains = self._get_dns()
        proxy_settings = self._get_proxy_settings(interfaces)
        wifi_networks = self._get_wifi_networks(interfaces)

        return NetworkConfig(
            interfaces=interfaces,
            dns_servers=dns_servers,
            search_domains=search_domains,
            proxy_settings=proxy_settings,
            wifi_networks=wifi_networks,
        )

    def _get_interfaces(self) -> list[NetworkInterface]:
        """Get all network interfaces in a single subprocess call."""
        result = run_command(["networksetup", "-listallhardwareports"])
        if result is None or result.returncode != 0:
            return []

        interfaces: list[NetworkInterface] = []
        ip_map = self._get_ip_addresses()

        current_port: str | None = None
        current_device: str | None = None

        for raw_line in result.stdout.splitlines():
            stripped = raw_line.strip()
            if stripped.startswith("Hardware Port:"):
                current_port = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("Device:"):
                current_device = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("Ethernet Address:"):
                # End of this interface block — emit the entry
                if current_port:
                    interfaces.append(
                        NetworkInterface(
                            name=current_port,
                            hardware_port=current_port,
                            device=current_device,
                            ip_address=ip_map.get(current_device or ""),
                        )
                    )
                current_port = None
                current_device = None

        return interfaces

    def _get_ip_addresses(self) -> dict[str, str]:
        """Get IP addresses for all interfaces via ifconfig (single call)."""
        result = run_command(["ifconfig"])
        if result is None or result.returncode != 0:
            return {}

        ip_map: dict[str, str] = {}
        current_iface = ""
        for raw_line in result.stdout.splitlines():
            # Interface header lines start at column 0
            if raw_line and not raw_line[0].isspace() and ":" in raw_line:
                current_iface = raw_line.split(":")[0]
            elif "inet " in raw_line and current_iface:
                match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", raw_line)
                if match and match.group(1) != "127.0.0.1":
                    ip_map[current_iface] = match.group(1)

        return ip_map

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
        # Try Wi-Fi service first, fall back to first interface
        service = "Wi-Fi"
        if not any(i.name == "Wi-Fi" for i in interfaces) and interfaces:
            service = interfaces[0].name

        for proxy_type, flag in [("http", "-getwebproxy"), ("https", "-getsecurewebproxy")]:
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

    def _get_wifi_networks(self, interfaces: list[NetworkInterface]) -> list[str]:
        networks: list[str] = []
        # Find Wi-Fi device name
        wifi_device = None
        for iface in interfaces:
            if iface.name == "Wi-Fi" and iface.device:
                wifi_device = iface.device
                break

        if wifi_device is None:
            wifi_device = "en0"

        result = run_command(["networksetup", "-getairportnetwork", wifi_device])
        if result is not None and result.returncode == 0:
            output = result.stdout.strip()
            if "Current Wi-Fi Network:" in output:
                network = output.split(":", 1)[1].strip()
                if network:
                    networks.append(network)

        return networks
