"""
Tests for ROPgadget MCP Server
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys

from mcp.models import (
    Gadget,
    GadgetSearchResult,
    BinaryInfo,
    CommandResult,
)
from mcp.tools import (
    find_gadgets,
    find_jop_gadgets,
    find_syscall_gadgets,
    get_binary_info,
    search_gadgets_by_pattern,
    run_ropgadget_command,
)


class TestModels:
    """Test data models"""

    def test_gadget(self):
        """Test Gadget model"""
        gadget = Gadget(
            address=0x400100,
            instruction="pop rdi ; ret",
            bytes="5fc3",
            category="rop"
        )
        result = gadget.to_dict()

        assert result["address"] == "0x400100"
        assert result["instruction"] == "pop rdi ; ret"
        assert result["bytes"] == "5fc3"
        assert result["category"] == "rop"

    def test_gadget_search_result(self):
        """Test GadgetSearchResult model"""
        gadgets = [
            Gadget(address=0x400100, instruction="pop rdi ; ret"),
            Gadget(address=0x400200, instruction="ret"),
        ]
        result_obj = GadgetSearchResult(
            gadgets=gadgets,
            total_count=2,
            binary_path="./binary",
            architecture="x86"
        )
        result = result_obj.to_dict()

        assert result["total_count"] == 2
        assert len(result["gadgets"]) == 2
        assert result["binary_path"] == "./binary"
        assert result["architecture"] == "x86"

    def test_binary_info(self):
        """Test BinaryInfo model"""
        info = BinaryInfo(
            path="./binary",
            architecture="x86",
            endian="Little",
            bits=64
        )
        result = info.to_dict()

        assert result["path"] == "./binary"
        assert result["architecture"] == "x86"
        assert result["endian"] == "Little"
        assert result["bits"] == 64

    def test_command_result(self):
        """Test CommandResult model"""
        result_obj = CommandResult(
            output="test output",
            error="",
            return_code=0
        )
        result = result_obj.to_dict()

        assert result["output"] == "test output"
        assert result["error"] == ""
        assert result["return_code"] == 0


class TestTools:
    """Test MCP tools"""

    @patch('mcp.tools.subprocess.run')
    def test_find_gadgets(self, mock_run):
        """Test find_gadgets tool"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="0x400100 : pop rdi ; ret\n0x400200 : ret\n",
            stderr=""
        )

        result = find_gadgets("./binary", depth=5)

        assert "gadgets" in result
        assert result["total_count"] >= 0
        assert result["binary_path"] == "./binary"

    @patch('mcp.tools.subprocess.run')
    def test_find_jop_gadgets(self, mock_run):
        """Test find_jop_gadgets tool"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="0x400100 : jmp rax\n",
            stderr=""
        )

        result = find_jop_gadgets("./binary", depth=5)

        assert "gadgets" in result
        assert result["binary_path"] == "./binary"

    @patch('mcp.tools.subprocess.run')
    def test_find_syscall_gadgets(self, mock_run):
        """Test find_syscall_gadgets tool"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="0x400100 : syscall\n",
            stderr=""
        )

        result = find_syscall_gadgets("./binary")

        assert "gadgets" in result
        assert result["binary_path"] == "./binary"

    @patch('mcp.tools.subprocess.run')
    def test_get_binary_info(self, mock_run):
        """Test get_binary_info tool"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Architecture: x86_64\nEndian: Little\nBits: 64\n",
            stderr=""
        )

        result = get_binary_info("./binary")

        assert result["path"] == "./binary"
        assert "architecture" in result

    @patch('mcp.tools.subprocess.run')
    def test_search_gadgets_by_pattern(self, mock_run):
        """Test search_gadgets_by_pattern tool"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="0x400100 : pop rdi ; ret\n",
            stderr=""
        )

        result = search_gadgets_by_pattern("./binary", "pop rdi")

        assert "gadgets" in result
        assert result["binary_path"] == "./binary"

    @patch('mcp.tools.subprocess.run')
    def test_run_ropgadget_command(self, mock_run):
        """Test run_ropgadget_command tool"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="test output",
            stderr=""
        )

        result = run_ropgadget_command("./binary", ["--depth", "10"])

        assert result["output"] == "test output"
        assert result["return_code"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])