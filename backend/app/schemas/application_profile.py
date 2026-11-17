"""Bounded, evidence-linked application surface inventory."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class ApplicationTechnology(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=160)
    observation_ids: list[str] = Field(min_length=1, max_length=500)
    evidence: str = Field(max_length=500)


class ApplicationRoute(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    host: str = Field(min_length=1, max_length=253)
    route_template: str = Field(min_length=1, max_length=1024)
    surfaces: list[Literal["authentication", "object_access", "account", "payment", "admin", "other"]] = Field(max_length=6)
    observation_ids: list[str] = Field(min_length=1, max_length=500)


class ApplicationHost(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    hostname: str = Field(min_length=1, max_length=253)
    observation_ids: list[str] = Field(min_length=1, max_length=500)


class ApplicationProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    profile_version: Literal["1"] = "1"
    source_observation_count: int = Field(ge=0, le=5000)
    hosts: list[ApplicationHost] = Field(max_length=500)
    technologies: list[ApplicationTechnology] = Field(max_length=500)
    routes: list[ApplicationRoute] = Field(max_length=1000)
    limitations: Literal[
        "Inventory reflects supplied observations only; names and technologies are not verified, and route labels do not establish behavior or vulnerabilities."
    ] = "Inventory reflects supplied observations only; names and technologies are not verified, and route labels do not establish behavior or vulnerabilities."
