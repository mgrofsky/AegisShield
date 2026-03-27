"""
OpenAI Client Management

Provides a cached singleton OpenAI client and unified chat completion functions.
Supports streaming, JSON mode, and vision (image analysis).

NIST SP 800-53 Rev. 5 Control Mappings:
- IA-5: Authenticator Management - API key handling
- SC-8: Transmission Confidentiality - Secure API communication
"""

import json
import logging
from typing import Any

import streamlit as st
from openai import OpenAI

from config import MODEL_CONFIG

logger = logging.getLogger(__name__)


@st.cache_resource
def get_openai_client(api_key: str) -> OpenAI:
    """Return a cached OpenAI client instance for the given API key."""
    logger.info("Creating new OpenAI client instance")
    return OpenAI(api_key=api_key)


def _get_model() -> str:
    """Resolve the current model from session state or config default."""
    return st.session_state.get("selected_model") or MODEL_CONFIG.default_model


def chat_completion(
    prompt: str,
    system_prompt: str = "You are a helpful assistant.",
    api_key: str | None = None,
    model: str | None = None,
    json_mode: bool = False,
    stream: bool = False,
) -> Any:
    """
    Unified chat completion call.

    Args:
        prompt: The user message.
        system_prompt: The system message.
        api_key: OpenAI API key. Defaults to session state.
        model: Model name. Defaults to session state / config.
        json_mode: If True, request JSON output.
        stream: If True, return a streaming iterator.

    Returns:
        If stream=False: the response content string (or parsed JSON dict if json_mode).
        If stream=True: the streaming iterator for use with st.write_stream().
    """
    key = api_key or st.session_state.get("openai_api_key", "")
    if not key:
        raise ValueError("OpenAI API key is required")

    model_name = model or _get_model()
    client = get_openai_client(key)

    kwargs: dict[str, Any] = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
    }

    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}

    if stream:
        kwargs["stream"] = True
        response = client.chat.completions.create(**kwargs)
        return response

    response = client.chat.completions.create(**kwargs)
    content = response.choices[0].message.content

    if json_mode:
        return json.loads(content)

    return content


def chat_completion_with_image(
    prompt: str,
    base64_image: str,
    api_key: str | None = None,
    model: str | None = None,
    max_tokens: int | None = None,
) -> str | None:
    """
    Chat completion with an image input (Vision API).

    Args:
        prompt: The analysis prompt.
        base64_image: Base64-encoded image data.
        api_key: OpenAI API key.
        model: Model name.
        max_tokens: Max tokens for the response.

    Returns:
        The response content string, or None on error.
    """
    key = api_key or st.session_state.get("openai_api_key", "")
    if not key:
        raise ValueError("OpenAI API key is required")

    model_name = model or _get_model()
    client = get_openai_client(key)
    tokens = max_tokens or MODEL_CONFIG.max_tokens_image_analysis

    try:
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"},
                        },
                    ],
                }
            ],
            max_tokens=tokens,
        )
        return response.choices[0].message.content
    except Exception as e:
        logger.error("Image analysis failed: %s", e)
        return None
