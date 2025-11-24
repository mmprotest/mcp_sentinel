from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

FilesystemMode = Literal["none", "read_only", "read_write"]


class ToolPolicy(BaseModel):
    """Policy describing a single MCP tool's permissions."""

    name: str
    outbound_http: bool = False
    allowed_domains: Optional[List[str]] = None
    filesystem: FilesystemMode = "none"

    @field_validator("allowed_domains")
    @classmethod
    def normalize_domains(cls, value):
        if value is None:
            return None
        return [v.lower() for v in value]


class ServerPolicy(BaseModel):
    name: Optional[str] = None
    owner: Optional[str] = None


class Policy(BaseModel):
    server: Optional[ServerPolicy] = None
    tools: List[ToolPolicy] = Field(default_factory=list)

    def get_tool(self, name: str) -> Optional[ToolPolicy]:
        for tool in self.tools:
            if tool.name == name:
                return tool
        return None
