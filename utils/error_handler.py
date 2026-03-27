"""
Centralized Error Handling Module

NIST SP 800-53 Rev. 5 Control Mappings:
- AU-3 (Content of Audit Records): Comprehensive logging with timestamps and context
- AU-4 (Audit Storage Capacity): Log file management and storage
- AU-6 (Audit Review, Analysis, and Reporting): Error analysis and reporting
- AU-8 (Time Stamps): Timestamp generation for all logged events
- SI-11 (Error Handling): Systematic error handling and user notification
"""

import logging
import traceback
from datetime import datetime
from pathlib import Path

import streamlit as st

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Configuration constants
LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "error.log"


def setup_logging() -> None:
    """
    Set up logging configuration and create log directory if it doesn't exist.

    NIST SP 800-53 Rev. 5 Controls Implemented:
    - AU-3: Content of Audit Records - Structured logging format
    - AU-4: Audit Storage Capacity - Log directory creation and management
    - AU-8: Time Stamps - Timestamp format configuration
    """
    try:
        LOG_DIR.mkdir(exist_ok=True)
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        logger.addHandler(file_handler)
        logger.info("Logging setup completed")
    except Exception as e:
        print(f"Error setting up logging: {e}")


def log_error(error_message: str, additional_info: str | None = None) -> None:
    """
    Log error details to file and console.

    NIST SP 800-53 Rev. 5 Controls Implemented:
    - AU-3: Content of Audit Records
    - AU-8: Time Stamps
    - AU-6: Audit Review
    - SI-11: Error Handling
    """
    # NIST AU-8: Precise timestamp for audit record
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # NIST AU-3: Structured log entry with context
    log_message = f"[{timestamp}] ERROR: {error_message}"
    if additional_info:
        log_message += f" | Info: {additional_info}"

    # NIST SI-11: Full traceback for systematic error analysis
    error_trace = traceback.format_exc()

    logger.error(log_message)
    if error_trace and error_trace.strip() != "NoneType: None":
        logger.error(error_trace)


def display_error_to_user(user_message: str) -> None:
    """
    Display an error message to the user in the Streamlit UI.

    NIST SP 800-53 Rev. 5 Controls Implemented:
    - SI-11: Error Handling - User-friendly error messages without sensitive details
    """
    st.error(user_message)


def handle_exception(
    exception: Exception, user_message: str = "An unexpected error occurred."
) -> None:
    """
    Centralized exception handler. Logs the error and displays a message to the user.

    NIST SP 800-53 Rev. 5 Controls Implemented:
    - SI-11: Error Handling
    - AU-3: Content of Audit Records
    - AU-6: Audit Review
    """
    log_error(str(exception))
    display_error_to_user(user_message)


# Set up logging when the module is imported
setup_logging()
