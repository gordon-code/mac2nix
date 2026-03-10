"""Display and audio hardware models."""

from __future__ import annotations

from pydantic import BaseModel


class NightShiftConfig(BaseModel):
    enabled: bool | None = None
    schedule: str | None = None


class Monitor(BaseModel):
    name: str
    resolution: str | None = None  # e.g. "3456x2234"
    scaling: float | None = None
    retina: bool = False
    arrangement_position: str | None = None  # e.g. "primary", "left", "right"
    refresh_rate: str | None = None
    color_profile: str | None = None


class DisplayConfig(BaseModel):
    monitors: list[Monitor] = []
    night_shift: NightShiftConfig | None = None
    true_tone_enabled: bool | None = None


class AudioDevice(BaseModel):
    name: str
    uid: str | None = None


class AudioConfig(BaseModel):
    input_devices: list[AudioDevice] = []
    output_devices: list[AudioDevice] = []
    default_input: str | None = None
    default_output: str | None = None
    alert_volume: float | None = None
    output_volume: int | None = None
    input_volume: int | None = None
    output_muted: bool | None = None
