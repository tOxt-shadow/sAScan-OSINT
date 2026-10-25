"""Built-in and optional scan modules."""

from sascan.modules.base import ModuleResult
from sascan.modules.email import scan_email
from sascan.modules.external import (
    TOOLS,
    available_tools,
    run_holehe,
    run_phoneinfoga,
    run_sherlock,
    tool_status,
)
from sascan.modules.gravatar import check_gravatar, gravatar_hash
from sascan.modules.phone import scan_phone
from sascan.modules.username import scan_username

__all__ = [
    "ModuleResult",
    "TOOLS",
    "available_tools",
    "check_gravatar",
    "gravatar_hash",
    "run_holehe",
    "run_phoneinfoga",
    "run_sherlock",
    "scan_email",
    "scan_phone",
    "scan_username",
    "tool_status",
]
