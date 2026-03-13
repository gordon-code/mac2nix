"""Network, security, and system configuration models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class NetworkInterface(BaseModel):
    name: str
    hardware_port: str | None = None
    device: str | None = None
    ip_address: str | None = None
    ipv6_address: str | None = None
    is_active: bool | None = None


class VpnProfile(BaseModel):
    name: str
    protocol: str | None = None
    status: str | None = None
    remote_address: str | None = None


class NetworkConfig(BaseModel):
    interfaces: list[NetworkInterface] = []
    dns_servers: list[str] = []
    search_domains: list[str] = []
    proxy_settings: dict[str, str] = {}
    wifi_networks: list[str] = []
    vpn_profiles: list[VpnProfile] = []
    proxy_bypass_domains: list[str] = []
    locations: list[str] = []
    current_location: str | None = None


class FirewallAppRule(BaseModel):
    app_path: str
    allowed: bool


class SecurityState(BaseModel):
    filevault_enabled: bool | None = None
    sip_enabled: bool | None = None
    firewall_enabled: bool | None = None
    gatekeeper_enabled: bool | None = None
    firewall_stealth_mode: bool | None = None
    firewall_app_rules: list[FirewallAppRule] = []
    firewall_block_all_incoming: bool | None = None
    touch_id_sudo: bool | None = None
    custom_certificates: list[str] = []


class TimeMachineConfig(BaseModel):
    configured: bool = False
    destination_name: str | None = None
    destination_id: str | None = None
    latest_backup: datetime | None = None


class PrinterInfo(BaseModel):
    name: str
    is_default: bool = False
    options: dict[str, str] = {}


class SystemExtension(BaseModel):
    """A system extension from /Library/SystemExtensions/."""

    identifier: str
    team_id: str | None = None
    version: str | None = None
    state: str | None = None


class ICloudState(BaseModel):
    """iCloud sync status — scan-only, cannot be configured via nix-darwin."""

    signed_in: bool = False
    desktop_sync: bool = False
    documents_sync: bool = False


class SystemConfig(BaseModel):
    hostname: str
    timezone: str | None = None
    locale: str | None = None
    power_settings: dict[str, str] = {}  # pmset key-value pairs
    spotlight_indexing: bool | None = None
    macos_version: str | None = None
    macos_build: str | None = None
    macos_product_name: str | None = None
    hardware_model: str | None = None
    hardware_chip: str | None = None
    hardware_memory: str | None = None
    hardware_serial: str | None = None
    time_machine: TimeMachineConfig | None = None
    software_update: dict[str, Any] = {}
    sleep_settings: dict[str, str | int | None] = {}
    login_window: dict[str, Any] = {}
    startup_chime: bool | None = None
    local_hostname: str | None = None
    dns_hostname: str | None = None
    network_time_enabled: bool | None = None
    network_time_server: str | None = None
    printers: list[PrinterInfo] = []
    remote_login: bool | None = None
    screen_sharing: bool | None = None
    file_sharing: bool | None = None
    rosetta_installed: bool | None = None
    system_extensions: list[SystemExtension] = []
    icloud: ICloudState = Field(default_factory=ICloudState)
    mdm_enrolled: bool | None = None
