"""
AegisShield Configuration Module

Centralizes all application constants, model configurations, and default values.
Single source of truth for settings used across the application.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ModelConfig:
    """Configuration for AI model settings."""
    available_models: tuple[str, ...] = ("gpt-5.4", "gpt-4o")
    default_model: str = "gpt-5.4"
    vision_capable_models: tuple[str, ...] = ("gpt-5.4", "gpt-4o")
    json_mode_system_prompt: str = "You are a helpful assistant designed to output JSON."
    max_tokens_image_analysis: int = 4000


@dataclass(frozen=True)
class RetryConfig:
    """Configuration for retry behavior."""
    max_retries: int = 3
    initial_delay: float = 1.0
    backoff_multiplier: float = 2.0


@dataclass(frozen=True)
class APIConfig:
    """Configuration for external API settings."""
    nvd_top_n: int = 10
    otx_max_results: int = 5
    otx_lookback_days: int = 2920
    mitre_max_techniques: int = 25
    mitre_rate_limit_min: int = 0
    mitre_rate_limit_max: int = 5


@dataclass(frozen=True)
class AppConfig:
    """Configuration for application UI and behavior."""
    page_title: str = "AegisShield Threat Modeler"
    page_icon: str = ":shield:"
    layout: str = "wide"
    initial_sidebar_state: str = "expanded"
    min_description_length: int = 50
    max_image_size_bytes: int = 10 * 1024 * 1024  # 10MB
    allowed_image_types: tuple[str, ...] = ("image/png", "image/jpeg", "image/jpg")
    logo_path: str = "aegisshield.png"
    logo_bw_path: str = "aegisshield-bw.png"


# Module-level singleton instances
MODEL_CONFIG = ModelConfig()
RETRY_CONFIG = RetryConfig()
API_CONFIG = APIConfig()
APP_CONFIG = AppConfig()
