"""Tests for the attack tree module."""

from unittest.mock import MagicMock, patch

from attack_tree import get_attack_tree


@patch('attack_tree.handle_exception')
def test_get_attack_tree_missing_api_key(mock_handle_exception):
    get_attack_tree("", prompt="test")
    assert mock_handle_exception.call_count == 2

@patch('attack_tree.handle_exception')
def test_get_attack_tree_missing_prompt(mock_handle_exception):
    get_attack_tree("fake_key", prompt=None)
    assert mock_handle_exception.call_count == 2

@patch('attack_tree.OpenAI')
def test_get_attack_tree_success(mock_openai):
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value.choices = [
        MagicMock(message=MagicMock(content="```mermaid\ngraph\n```"))
    ]
    mock_openai.return_value = mock_client

    result = get_attack_tree("fake_key", prompt="test")
    assert "graph" in result
    mock_client.chat.completions.create.assert_called_once() 