"""Network, security, and system configuration models."""

from __future__ import annotations

from pydantic import BaseModel


class NetworkInterface(BaseModel):
    name: str
    hardware_port: str | None = None
    device: str | None = None
    ip_address: str | None = None


class NetworkConfig(BaseModel):
    interfaces: list[NetworkInterface] = []
    dns_servers: list[str] = []
    search_domains: list[str] = []
    proxy_settings: dict[str, str] = {}
    wifi_networks: list[str] = []


class SecurityState(BaseModel):
    filevault_enabled: bool | None = None
    sip_enabled: bool | None = None
    firewall_enabled: bool | None = None
    gatekeeper_enabled: bool | None = None
    tcc_summary: dict[str, list[str]] = {}  # service -> list of allowed apps


class SystemConfig(BaseModel):
    hostname: str
    timezone: str | None = None
    locale: str | None = None
    power_settings: dict[str, str] = {}  # pmset key-value pairs
    spotlight_indexing: bool | None = None
