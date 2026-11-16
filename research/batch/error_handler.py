import logging
import os
import traceback
from datetime import datetime
from pathlib import Path

import streamlit as st

# NIST SP 800-53 Rev. 5 Control Mappings:
# - AU-3 (Content of Audit Records): Comprehensive logging with timestamps and context
# - AU-4 (Audit Storage Capacity): Log file management and storage
# - AU-6 (Audit Review, Analysis, and Reporting): Error analysis and reporting
# - AU-8 (Time Stamps): Timestamp generation for all logged events
# - SI-11 (Error Handling): Systematic error handling and user notification

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
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
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logger.addHandler(file_handler)
        logger.info("Logging setup completed")
    except Exception as e:
        print(f"Error setting up logging: {str(e)}")

def log_error(error_message: str, additional_info: str | None = None) -> None:
    """
    Logs the error details to both file and console with timestamp and traceback.
    
    NIST SP 800-53 Rev. 5 Controls Implemented:
    - AU-3: Content of Audit Records - Complete error context and metadata
    - AU-8: Time Stamps - Precise timestamp for each error event
    - AU-6: Audit Review - Structured format for analysis
    - SI-11: Error Handling - Comprehensive error capture and logging
    
    Args:
        error_message (str): The main error message to log
        additional_info (Optional[str]): Any additional context or information about the error
    """
    # NIST AU-8: Time Stamps - Generate precise timestamp for audit record
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # NIST AU-3: Content of Audit Records - Structured log entry with context
    log_message = f"[{timestamp}] ERROR: {error_message}"
    if additional_info:
        log_message += f" | Info: {additional_info}"

    # NIST AU-6: Write to console for immediate audit review
    os.write(1, log_message.encode())

    # NIST SI-11: Log the full traceback for systematic error analysis
    error_trace = traceback.format_exc()
    os.write(1, error_trace.encode())

    # Log to file and Streamlit logger
    logger.error(log_message)
    logger.error(error_trace)

def display_error_to_user(user_message: str) -> None:
    """
    Displays an error message to the user in the Streamlit UI.
    
    NIST SP 800-53 Rev. 5 Controls Implemented:
    - SI-11: Error Handling - User-friendly error messages without sensitive details
    - AU-6: Audit Review - User notification as part of error handling process
    
    Args:
        user_message (str): The error message to display to the user
    """
    # NIST SI-11: Display sanitized error message to user (no sensitive data exposure)
    st.error(user_message)

def handle_exception(exception: Exception, user_message: str = "An unexpected error occurred.") -> None:
    """
    Centralized function to handle exceptions.
    Logs the error to both file and console, and displays a message to the user.
    
    NIST SP 800-53 Rev. 5 Controls Implemented:
    - SI-11: Error Handling - Centralized exception management
    - AU-3: Content of Audit Records - Complete exception context capture
    - AU-6: Audit Review - Error logging for analysis
    
    Args:
        exception (Exception): The exception that was caught
        user_message (str): A user-friendly message to display in the UI
    """
    error_message = str(exception)
    log_error(error_message)
    display_error_to_user(user_message)

# Set up logging when the module is imported
setup_logging()
