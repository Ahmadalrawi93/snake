import pytest

from app import mcp_server


def test_mcp_operator_identity_fails_closed_when_missing(monkeypatch):
    monkeypatch.delenv("SNAKE_MCP_USER_ID", raising=False)
    with pytest.raises(RuntimeError, match="SNAKE_MCP_USER_ID"):
        mcp_server._operator_id()


@pytest.mark.parametrize("value", ["0", "-1", "1.5", "operator", ""])
def test_mcp_operator_identity_rejects_invalid_values(monkeypatch, value):
    monkeypatch.setenv("SNAKE_MCP_USER_ID", value)
    with pytest.raises(RuntimeError, match="SNAKE_MCP_USER_ID"):
        mcp_server._operator_id()


def test_mcp_operator_identity_accepts_positive_integer(monkeypatch):
    monkeypatch.setenv("SNAKE_MCP_USER_ID", "17")
    assert mcp_server._operator_id() == 17


def test_mcp_json_output_is_compact_and_preserves_unicode():
    assert mcp_server._json({"target": "مثال.test"}) == '{"target":"مثال.test"}'



def test_mcp_url_output_redacts_query_and_fragment():
    assert mcp_server._redact_url_query(
        "https://example.test/path?token=secret#section"
    ) == "https://example.test/path"
