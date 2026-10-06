"""
SentinelMesh AI knowledge base.

The knowledge base contains two separate knowledge sources:

1. General security knowledge
2. SentinelMesh-specific knowledge

Knowledge retrieved from this module provides context to the AI.
It must never be treated as proof that an event occurred.
"""

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass(frozen=True)
class KnowledgeDocument:
    """
    One document in the SentinelMesh knowledge base.
    """

    document_id: str
    title: str
    content: str
    source_type: str
    metadata: Dict[str, Any]


# -------------------------------------------------------------------
# GENERAL SECURITY KNOWLEDGE
# -------------------------------------------------------------------

SECURITY_KNOWLEDGE: List[KnowledgeDocument] = [

    KnowledgeDocument(
        document_id="SEC-WINDOWS-4672",
        title="Windows Event ID 4672",
        content=(
            "Windows Security Event ID 4672 indicates that special "
            "privileges were assigned to a new logon. The event can "
            "provide useful security context, but the event alone "
            "does not establish malicious activity."
        ),
        source_type="security_knowledge",
        metadata={
            "event_id": "4672",
            "category": "special_privileges",
        },
    ),

    KnowledgeDocument(
        document_id="SEC-WINDOWS-4798",
        title="Windows Event ID 4798",
        content=(
            "Windows Security Event ID 4798 represents a process "
            "enumerating the members of a security-enabled local "
            "group. This can provide account-discovery context."
        ),
        source_type="security_knowledge",
        metadata={
            "event_id": "4798",
            "category": "account_discovery",
        },
    ),

    KnowledgeDocument(
        document_id="SEC-CREDENTIAL-ACCESS",
        title="Credential Access",
        content=(
            "Credential access activity involves attempts to obtain "
            "credentials or authentication material. Credential "
            "access indicators require surrounding event and process "
            "context before malicious intent can be established."
        ),
        source_type="security_knowledge",
        metadata={
            "category": "credential_access",
        },
    ),

    KnowledgeDocument(
        document_id="SEC-ACCOUNT-DISCOVERY",
        title="Account Discovery",
        content=(
            "Account discovery is the identification of accounts, "
            "users, or groups in an environment. It may occur during "
            "normal administration as well as during malicious activity."
        ),
        source_type="security_knowledge",
        metadata={
            "category": "discovery",
        },
    ),

    KnowledgeDocument(
        document_id="SEC-CORRELATION",
        title="Security Event Correlation",
        content=(
            "Correlation combines multiple security observations "
            "within a defined time or contextual relationship. "
            "Correlation increases investigative context but does "
            "not automatically prove malicious activity."
        ),
        source_type="security_knowledge",
        metadata={
            "category": "correlation",
        },
    ),

    KnowledgeDocument(
        document_id="SEC-SYNTHETIC-TELEMETRY",
        title="Synthetic Security Telemetry",
        content=(
            "Synthetic telemetry is generated or simulated data used "
            "for testing and analysis. Synthetic observations must "
            "remain explicitly identified as synthetic and must not "
            "be represented as confirmed real-world malicious activity."
        ),
        source_type="security_knowledge",
        metadata={
            "category": "telemetry",
            "synthetic": "true",
        },
    ),
]


# -------------------------------------------------------------------
# SENTINELMESH-SPECIFIC KNOWLEDGE
# -------------------------------------------------------------------

SENTINELMESH_KNOWLEDGE: List[KnowledgeDocument] = [

    KnowledgeDocument(
        document_id="SM-RULE-001",
        title="SM-001 Special Privileges Assigned",
        content=(
            "SentinelMesh rule SM-001 detects Windows Event ID 4672 "
            "and categorizes the observation as privilege-related "
            "activity with medium severity."
        ),
        source_type="sentinelmesh_knowledge",
        metadata={
            "rule_id": "SM-001",
            "event_id": "4672",
            "category": "privilege",
        },
    ),

    KnowledgeDocument(
        document_id="SM-RULE-002",
        title="SM-002 User Account Enumeration",
        content=(
            "SentinelMesh rule SM-002 detects Windows Event ID 4798 "
            "and represents the activity as account discovery."
        ),
        source_type="sentinelmesh_knowledge",
        metadata={
            "rule_id": "SM-002",
            "event_id": "4798",
            "category": "account_discovery",
        },
    ),

    KnowledgeDocument(
        document_id="SM-RULE-003",
        title="SM-003 Credential Manager Activity",
        content=(
            "SentinelMesh rule SM-003 represents Credential Manager "
            "activity and categorizes the detection as credential access."
        ),
        source_type="sentinelmesh_knowledge",
        metadata={
            "rule_id": "SM-003",
            "event_id": "5379",
            "category": "credential_access",
        },
    ),

    KnowledgeDocument(
        document_id="SM-CM-001",
        title="CM-001 Account Discovery Followed by Credential Activity",
        content=(
            "SentinelMesh correlation rule CM-001 correlates account "
            "discovery followed by Credential Manager activity on "
            "the same host within the configured correlation window."
        ),
        source_type="sentinelmesh_knowledge",
        metadata={
            "correlation_rule": "CM-001",
            "category": "correlation",
        },
    ),

    KnowledgeDocument(
        document_id="SM-BT-001",
        title="BT-001 Suspicious Script Execution",
        content=(
            "SentinelMesh behavioral rule BT-001 identifies synthetic "
            "script execution telemetry and maps it to execution context."
        ),
        source_type="sentinelmesh_knowledge",
        metadata={
            "rule_id": "BT-001",
            "category": "execution",
        },
    ),

    KnowledgeDocument(
        document_id="SM-BT-002",
        title="BT-002 Possible Command and Control Activity",
        content=(
            "SentinelMesh behavioral rule BT-002 identifies synthetic "
            "command-and-control indicators."
        ),
        source_type="sentinelmesh_knowledge",
        metadata={
            "rule_id": "BT-002",
            "category": "command_and_control",
        },
    ),

    KnowledgeDocument(
        document_id="SM-BT-003",
        title="BT-003 Browser Data Access Indicator",
        content=(
            "SentinelMesh behavioral rule BT-003 identifies synthetic "
            "browser data access indicators and associates them with "
            "credential-access context."
        ),
        source_type="sentinelmesh_knowledge",
        metadata={
            "rule_id": "BT-003",
            "category": "credential_access",
        },
    ),

    KnowledgeDocument(
        document_id="SM-BT-004",
        title="BT-004 Persistence Activity Indicator",
        content=(
            "SentinelMesh behavioral rule BT-004 identifies synthetic "
            "persistence activity indicators."
        ),
        source_type="sentinelmesh_knowledge",
        metadata={
            "rule_id": "BT-004",
            "category": "persistence",
        },
    ),

    KnowledgeDocument(
        document_id="SM-BT-005",
        title="BT-005 Privilege Activity Indicator",
        content=(
            "SentinelMesh behavioral rule BT-005 identifies synthetic "
            "privilege-related behavioral indicators."
        ),
        source_type="sentinelmesh_knowledge",
        metadata={
            "rule_id": "BT-005",
            "category": "privilege",
        },
    ),

    KnowledgeDocument(
        document_id="SM-SYNTHETIC",
        title="SentinelMesh Synthetic Telemetry Policy",
        content=(
            "SentinelMesh synthetic behavior telemetry must remain "
            "marked with synthetic=true. Synthetic telemetry is "
            "investigative context and must not be presented as "
            "confirmed real malicious activity."
        ),
        source_type="sentinelmesh_knowledge",
        metadata={
            "category": "telemetry",
            "synthetic": "true",
        },
    ),

    KnowledgeDocument(
        document_id="SM-ATTRIBUTION",
        title="SentinelMesh Behavioral Profile Attribution",
        content=(
            "A behavioral profile match in SentinelMesh represents "
            "contextual alignment with observed behavior. It does "
            "not confirm attribution to a specific malware family."
        ),
        source_type="sentinelmesh_knowledge",
        metadata={
            "category": "attribution",
            "status": "behavioral_profile_match_only",
        },
    ),

    KnowledgeDocument(
        document_id="SM-RISK",
        title="SentinelMesh Risk Scoring",
        content=(
            "SentinelMesh risk scoring combines detection severity, "
            "behavioral evidence, correlation strength, MITRE context, "
            "threat-profile alignment, persistence or privilege "
            "indicators, network activity, and repetition."
        ),
        source_type="sentinelmesh_knowledge",
        metadata={
            "category": "risk_scoring",
            "model_version": "SentinelMesh-Risk-v3",
        },
    ),
]


def get_security_knowledge() -> List[KnowledgeDocument]:
    """
    Return general security knowledge.
    """

    return list(SECURITY_KNOWLEDGE)


def get_sentinelmesh_knowledge() -> List[KnowledgeDocument]:
    """
    Return SentinelMesh-specific knowledge.
    """

    return list(SENTINELMESH_KNOWLEDGE)


__all__ = [
    "KnowledgeDocument",
    "SECURITY_KNOWLEDGE",
    "SENTINELMESH_KNOWLEDGE",
    "get_security_knowledge",
    "get_sentinelmesh_knowledge",
]