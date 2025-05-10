import logging
import os
import traceback
from datetime import datetime
from pathlib import Path

import streamlit as st

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
    
    Args:
        error_message (str): The main error message to log
        additional_info (Optional[str]): Any additional context or information about the error
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] ERROR: {error_message}"
    if additional_info:
        log_message += f" | Info: {additional_info}"

    # Write to console
    os.write(1, log_message.encode())

    # Log the full traceback for better debugging
    error_trace = traceback.format_exc()
    os.write(1, error_trace.encode())

    # Log to file and Streamlit logger
    logger.error(log_message)
    logger.error(error_trace)

def display_error_to_user(user_message: str) -> None:
    """
    Displays an error message to the user in the Streamlit UI.
    
    Args:
        user_message (str): The error message to display to the user
    """
    st.error(user_message)

def handle_exception(exception: Exception, user_message: str = "An unexpected error occurred.") -> None:
    """
    Centralized function to handle exceptions.
    Logs the error to both file and console, and displays a message to the user.
    
    Args:
        exception (Exception): The exception that was caught
        user_message (str): A user-friendly message to display in the UI
    """
    error_message = str(exception)
    log_error(error_message)
    display_error_to_user(user_message)

# Set up logging when the module is imported
setup_logging()
