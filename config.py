"""Centralized configuration constants for AegisShield."""

# Model configuration
DEFAULT_MODEL_NAME = "gpt-5.4"
MODEL_OPTIONS = ["gpt-5.4"]

# Retry configuration
MAX_RETRIES = 3
INITIAL_RETRY_DELAY = 1.0

# MITRE ATT&CK processing
MAX_TECHNIQUES = 25
RATE_LIMIT_SLEEP_MIN = 0
RATE_LIMIT_SLEEP_MAX = 5
