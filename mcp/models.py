"""
Data models for ROPgadget MCP Server

These models define the structured output format for MCP tools,
ensuring consistent JSON responses for AI Agent consumption.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Gadget:
    """ROP gadget information."""
    address: int
    instruction: str
    bytes: str = ""
    category: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "instruction": self.instruction,
            "bytes": self.bytes,
            "category": self.category,
        }


@dataclass
class GadgetSearchResult:
    """Gadget search result."""
    gadgets: List[Gadget] = field(default_factory=list)
    total_count: int = 0
    binary_path: str = ""
    architecture: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gadgets": [g.to_dict() for g in self.gadgets],
            "total_count": self.total_count,
            "binary_path": self.binary_path,
            "architecture": self.architecture,
        }


@dataclass
class BinaryInfo:
    """Binary file information."""
    path: str
    architecture: str
    endian: str
    bits: int
    sections: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "architecture": self.architecture,
            "endian": self.endian,
            "bits": self.bits,
            "sections": self.sections,
        }


@dataclass
class CommandResult:
    """Command execution result."""
    output: str = ""
    error: str = ""
    return_code: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "output": self.output,
            "error": self.error,
            "return_code": self.return_code,
        }
