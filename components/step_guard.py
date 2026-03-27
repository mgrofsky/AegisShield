"""
Step Guard Component

Provides a reusable prerequisite check for pages that depend on prior steps.
"""

import streamlit as st


def require_steps_completed(*steps: int) -> bool:
    """
    Check that all specified steps are completed.
    Displays a warning if any are not.

    Args:
        *steps: Step numbers that must be completed.

    Returns:
        True if all steps are completed, False otherwise.
    """
    for step in steps:
        if not st.session_state.get(f"step{step}_completed", False):
            step_names = {
                1: "Description", 2: "Technology", 3: "Threat Model",
                4: "Mitigations", 5: "DREAD Assessment", 6: "Test Cases",
            }
            name = step_names.get(step, f"Step {step}")
            st.warning(f"Please complete Step {step}: {name} first.")
            return False
    return True
