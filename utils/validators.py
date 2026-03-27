"""
Input Validation Utilities

Provides reusable validation functions for user inputs across all pages.
"""

import re

from config import APP_CONFIG


def validate_description(description: str) -> tuple[bool, str | None]:
    """Validate the application description meets minimum requirements."""
    if not description or len(description.strip()) < APP_CONFIG.min_description_length:
        return False, f"Please provide a description with at least {APP_CONFIG.min_description_length} characters."
    return True, None


def validate_image(uploaded_file) -> tuple[bool, str | None]:
    """Validate an uploaded image file (size and type)."""
    if uploaded_file.size > APP_CONFIG.max_image_size_bytes:
        return False, "Image file is too large. Maximum size is 10MB."
    if uploaded_file.type not in APP_CONFIG.allowed_image_types:
        return False, "Invalid image type. Please upload a PNG or JPEG file."
    return True, None


def validate_version_format(version: str) -> tuple[bool, str]:
    """Validate a technology version string format."""
    if not version:
        return True, ""
    pattern = r"^(\d+|\*)(\.(\d+|\*))*$"
    if not re.match(pattern, version):
        return False, "Version should be in format: numbers or wildcards separated by dots (e.g., '1.2.3', '1.2.*')"
    if len(version.split(".")) > 4:
        return False, "Version should not have more than 4 segments (e.g., '1.2.3.4')"
    return True, ""
