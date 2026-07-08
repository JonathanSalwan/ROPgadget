"""
MCP Tools implementation for ROPgadget

This module implements the MCP tools that expose ROPgadget's core functionality
to AI Agents via the Model Context Protocol.
"""

from __future__ import annotations

import subprocess
import json
from typing import Any, Dict, List

from .models import (
    Gadget,
    GadgetSearchResult,
    BinaryInfo,
    CommandResult,
)


def find_gadgets(binary_path: str, depth: int = 5, only: str = None, range: str = None) -> Dict[str, Any]:
    """
    Find ROP gadgets in a binary file.

    Args:
        binary_path: Path to the binary file
        depth: Maximum gadget depth (default: 5)
        only: Only show gadgets matching this regex
        range: Search in specific address range (e.g., "0x400000-0x401000")

    Returns:
        GadgetSearchResult with found gadgets
    """
    try:
        cmd = ["ROPgadget", "--binary", binary_path, "--depth", str(depth)]

        if only:
            cmd.extend(["--only", only])

        if range:
            cmd.extend(["--range", range])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        gadgets = []
        if result.returncode == 0:
            # Parse ROPgadget output
            for line in result.stdout.split("\n"):
                if "0x" in line and ":" in line:
                    parts = line.strip().split(" : ")
                    if len(parts) >= 2:
                        addr_str = parts[0].strip()
                        instruction = parts[1].strip()

                        try:
                            addr = int(addr_str, 16)
                            gadget = Gadget(
                                address=addr,
                                instruction=instruction,
                                category="rop"
                            )
                            gadgets.append(gadget)
                        except ValueError:
                            continue

        search_result = GadgetSearchResult(
            gadgets=gadgets,
            total_count=len(gadgets),
            binary_path=binary_path,
            architecture="unknown"  # Would need to parse from ROPgadget output
        )
        return search_result.to_dict()
    except Exception as e:
        return {"error": str(e), "gadgets": []}


def find_jop_gadgets(binary_path: str, depth: int = 5) -> Dict[str, Any]:
    """
    Find JOP (Jump-Oriented Programming) gadgets in a binary file.

    Args:
        binary_path: Path to the binary file
        depth: Maximum gadget depth (default: 5)

    Returns:
        GadgetSearchResult with found JOP gadgets
    """
    try:
        cmd = ["ROPgadget", "--binary", binary_path, "--depth", str(depth), "--jop"]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        gadgets = []
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "0x" in line and ":" in line:
                    parts = line.strip().split(" : ")
                    if len(parts) >= 2:
                        addr_str = parts[0].strip()
                        instruction = parts[1].strip()

                        try:
                            addr = int(addr_str, 16)
                            gadget = Gadget(
                                address=addr,
                                instruction=instruction,
                                category="jop"
                            )
                            gadgets.append(gadget)
                        except ValueError:
                            continue

        search_result = GadgetSearchResult(
            gadgets=gadgets,
            total_count=len(gadgets),
            binary_path=binary_path,
            architecture="unknown"
        )
        return search_result.to_dict()
    except Exception as e:
        return {"error": str(e), "gadgets": []}


def find_syscall_gadgets(binary_path: str) -> Dict[str, Any]:
    """
    Find syscall gadgets in a binary file.

    Args:
        binary_path: Path to the binary file

    Returns:
        GadgetSearchResult with found syscall gadgets
    """
    try:
        cmd = ["ROPgadget", "--binary", binary_path, "--syscall"]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        gadgets = []
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "0x" in line and ":" in line:
                    parts = line.strip().split(" : ")
                    if len(parts) >= 2:
                        addr_str = parts[0].strip()
                        instruction = parts[1].strip()

                        try:
                            addr = int(addr_str, 16)
                            gadget = Gadget(
                                address=addr,
                                instruction=instruction,
                                category="syscall"
                            )
                            gadgets.append(gadget)
                        except ValueError:
                            continue

        search_result = GadgetSearchResult(
            gadgets=gadgets,
            total_count=len(gadgets),
            binary_path=binary_path,
            architecture="unknown"
        )
        return search_result.to_dict()
    except Exception as e:
        return {"error": str(e), "gadgets": []}


def get_binary_info(binary_path: str) -> Dict[str, Any]:
    """
    Get information about a binary file.

    Args:
        binary_path: Path to the binary file

    Returns:
        BinaryInfo with file details
    """
    try:
        cmd = ["ROPgadget", "--binary", binary_path, "--info"]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        info = BinaryInfo(
            path=binary_path,
            architecture="unknown",
            endian="unknown",
            bits=0
        )

        if result.returncode == 0:
            # Parse ROPgadget info output
            for line in result.stdout.split("\n"):
                if "Architecture" in line:
                    info.architecture = line.split(":")[1].strip()
                elif "Endian" in line:
                    info.endian = line.split(":")[1].strip()
                elif "Bits" in line:
                    try:
                        info.bits = int(line.split(":")[1].strip())
                    except ValueError:
                        pass

        return info.to_dict()
    except Exception as e:
        return {"error": str(e)}


def search_gadgets_by_pattern(binary_path: str, pattern: str) -> Dict[str, Any]:
    """
    Search for gadgets matching a specific instruction pattern.

    Args:
        binary_path: Path to the binary file
        pattern: Instruction pattern to search for (e.g., "pop rdi", "ret")

    Returns:
        GadgetSearchResult with matching gadgets
    """
    try:
        cmd = ["ROPgadget", "--binary", binary_path, "--only", pattern]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        gadgets = []
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "0x" in line and ":" in line:
                    parts = line.strip().split(" : ")
                    if len(parts) >= 2:
                        addr_str = parts[0].strip()
                        instruction = parts[1].strip()

                        try:
                            addr = int(addr_str, 16)
                            gadget = Gadget(
                                address=addr,
                                instruction=instruction,
                                category="rop"
                            )
                            gadgets.append(gadget)
                        except ValueError:
                            continue

        search_result = GadgetSearchResult(
            gadgets=gadgets,
            total_count=len(gadgets),
            binary_path=binary_path,
            architecture="unknown"
        )
        return search_result.to_dict()
    except Exception as e:
        return {"error": str(e), "gadgets": []}


def run_ropgadget_command(binary_path: str, args: List[str]) -> Dict[str, Any]:
    """
    Run ROPgadget with custom arguments.

    Args:
        binary_path: Path to the binary file
        args: List of additional arguments for ROPgadget

    Returns:
        CommandResult with output
    """
    try:
        cmd = ["ROPgadget", "--binary", binary_path] + args

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        cmd_result = CommandResult(
            output=result.stdout,
            error=result.stderr,
            return_code=result.returncode
        )
        return cmd_result.to_dict()
    except Exception as e:
        return {"error": str(e)}


# Tool registry for MCP Server
TOOLS = {
    "find_gadgets": {
        "function": find_gadgets,
        "description": "Find ROP gadgets in a binary file",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary file",
                },
                "depth": {
                    "type": "integer",
                    "description": "Maximum gadget depth (default: 5)",
                    "default": 5,
                },
                "only": {
                    "type": "string",
                    "description": "Only show gadgets matching this regex",
                },
                "range": {
                    "type": "string",
                    "description": "Search in specific address range (e.g., '0x400000-0x401000')",
                },
            },
            "required": ["binary_path"],
        },
    },
    "find_jop_gadgets": {
        "function": find_jop_gadgets,
        "description": "Find JOP (Jump-Oriented Programming) gadgets in a binary file",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary file",
                },
                "depth": {
                    "type": "integer",
                    "description": "Maximum gadget depth (default: 5)",
                    "default": 5,
                },
            },
            "required": ["binary_path"],
        },
    },
    "find_syscall_gadgets": {
        "function": find_syscall_gadgets,
        "description": "Find syscall gadgets in a binary file",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary file",
                },
            },
            "required": ["binary_path"],
        },
    },
    "get_binary_info": {
        "function": get_binary_info,
        "description": "Get information about a binary file",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary file",
                },
            },
            "required": ["binary_path"],
        },
    },
    "search_gadgets_by_pattern": {
        "function": search_gadgets_by_pattern,
        "description": "Search for gadgets matching a specific instruction pattern",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary file",
                },
                "pattern": {
                    "type": "string",
                    "description": "Instruction pattern to search for (e.g., 'pop rdi', 'ret')",
                },
            },
            "required": ["binary_path", "pattern"],
        },
    },
    "run_ropgadget_command": {
        "function": run_ropgadget_command,
        "description": "Run ROPgadget with custom arguments",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary file",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of additional arguments for ROPgadget",
                },
            },
            "required": ["binary_path", "args"],
        },
    },
}
