"""Singleton OpenAI client using Streamlit's cache_resource."""

import streamlit as st
from openai import OpenAI


@st.cache_resource
def get_openai_client(api_key: str) -> OpenAI:
    """Return a cached OpenAI client for the given API key.

    The client is created once per unique api_key and reused across
    Streamlit reruns for the lifetime of the session.
    """
    return OpenAI(api_key=api_key)
