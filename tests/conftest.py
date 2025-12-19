"""Pytest configuration and fixtures."""

import pytest
import sys
from pathlib import Path

# Add src directory to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))


@pytest.fixture
def sample_action():
    """Sample action for testing."""
    from core.protocol import Action
    return Action(
        action_type="data_access",
        description="Access customer database",
        parameters={"database": "customers", "purpose": "analytics"}
    )


@pytest.fixture
def sample_reasoning():
    """Sample reasoning pathway for testing."""
    from core.protocol import ReasoningPathway, ReasoningStep
    return ReasoningPathway(
        steps=[
            ReasoningStep(1, "User requested analytics", 0.95),
            ReasoningStep(2, "Data needed for processing", 0.90)
        ],
        conclusion="Data access justified"
    )


@pytest.fixture
def keypair():
    """Generate a test keypair."""
    from core.crypto import generate_keypair
    return generate_keypair()
