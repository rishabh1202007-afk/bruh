import json
import os
from typing import Any, Dict, List, Optional

import mysql.connector
from mysql.connector import Error


# ============================================================
# MYSQL CONFIGURATION
# ============================================================

MYSQL_HOST = os.getenv(
    "MYSQL_HOST",
    "127.0.0.1",
)

MYSQL_PORT = int(
    os.getenv(
        "MYSQL_PORT",
        "3306",
    )
)

MYSQL_USER = os.getenv(
    "MYSQL_USER",
    "root",
)

MYSQL_PASSWORD = os.getenv(
    "MYSQL_PASSWORD",
    "",
)

MYSQL_DATABASE = os.getenv(
    "MYSQL_DATABASE",
    "sentinelmesh",
)


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():
    """
    Create and return a connection to the SentinelMesh
    MySQL database.
    """

    try:
        connection = mysql.connector.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE,
        )

        return connection

    except Error as exc:
        raise RuntimeError(
            f"Could not connect to MySQL database "
            f"'{MYSQL_DATABASE}': {exc}"
        ) from exc


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def initialize_database() -> None:
    """
    Create all SentinelMesh database tables if they do not
    already exist.
    """

    connection = get_connection()
    cursor = connection.cursor()

    try:

        # ----------------------------------------------------
        # INCIDENTS
        # ----------------------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id VARCHAR(255) PRIMARY KEY,

                timestamp VARCHAR(64),
                host VARCHAR(255),

                incident_type VARCHAR(255),
                severity VARCHAR(50),

                correlation_rule VARCHAR(255),
                rule_name VARCHAR(255),

                threat_profile VARCHAR(255),

                time_window_seconds INT,

                status VARCHAR(50),

                risk_score DECIMAL(6,2),
                risk_level VARCHAR(50),
                risk_model_version VARCHAR(100),

                synthetic_evidence BOOLEAN NOT NULL DEFAULT FALSE,

                attribution_status VARCHAR(100),

                incident_json JSON NOT NULL,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP
            )
            """
        )

        # ----------------------------------------------------
        # INCIDENT EVIDENCE
        # ----------------------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_evidence (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,

                incident_id VARCHAR(255) NOT NULL,

                evidence_index INT NOT NULL,

                source VARCHAR(255),

                rule_id VARCHAR(255),
                rule_name VARCHAR(255),

                severity VARCHAR(50),

                source_record VARCHAR(255),

                detection_id VARCHAR(255),

                behavior_type VARCHAR(255),

                evidence_json JSON NOT NULL,

                CONSTRAINT fk_evidence_incident
                    FOREIGN KEY (incident_id)
                    REFERENCES incidents(incident_id)
                    ON DELETE CASCADE,

                INDEX idx_evidence_incident (
                    incident_id
                )
            )
            """
        )

        # ----------------------------------------------------
        # INCIDENT MITRE TECHNIQUES
        # ----------------------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_techniques (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,

                incident_id VARCHAR(255) NOT NULL,

                technique_id VARCHAR(100) NOT NULL,

                technique_name VARCHAR(255),

                tactic VARCHAR(255),

                technique_source VARCHAR(100),

                technique_json JSON NOT NULL,

                CONSTRAINT fk_technique_incident
                    FOREIGN KEY (incident_id)
                    REFERENCES incidents(incident_id)
                    ON DELETE CASCADE,

                INDEX idx_technique_incident (
                    incident_id
                ),

                INDEX idx_technique_id (
                    technique_id
                )
            )
            """
        )

        # ----------------------------------------------------
        # INCIDENT ENTITIES
        # ----------------------------------------------------
        #
        # IMPORTANT:
        # entity_value is VARCHAR(255), not VARCHAR(500).
        # This keeps the combined UNIQUE index safely below
        # MySQL's 3072-byte index limit.
        #
        # Supported entities include:
        # host, user, process, ip
        # ----------------------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_entities (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,

                incident_id VARCHAR(255) NOT NULL,

                entity_type VARCHAR(64) NOT NULL,

                entity_value VARCHAR(255) NOT NULL,

                CONSTRAINT fk_entity_incident
                    FOREIGN KEY (incident_id)
                    REFERENCES incidents(incident_id)
                    ON DELETE CASCADE,

                UNIQUE KEY uq_incident_entity (
                    incident_id,
                    entity_type,
                    entity_value
                ),

                INDEX idx_entity_incident (
                    incident_id
                ),

                INDEX idx_entity_type_value (
                    entity_type,
                    entity_value
                )
            )
            """
        )

        # ----------------------------------------------------
        # INCIDENT RISK FACTORS
        # ----------------------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_risk_factors (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,

                incident_id VARCHAR(255) NOT NULL,

                factor_name VARCHAR(255) NOT NULL,

                score DECIMAL(6,2),

                maximum DECIMAL(6,2),

                factor_json JSON NOT NULL,

                CONSTRAINT fk_risk_factor_incident
                    FOREIGN KEY (incident_id)
                    REFERENCES incidents(incident_id)
                    ON DELETE CASCADE,

                INDEX idx_risk_factor_incident (
                    incident_id
                )
            )
            """
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()


# ============================================================
# JSON SERIALIZATION
# ============================================================

def _json(value: Any) -> str:
    """
    Convert a Python value into JSON suitable for storage
    in a MySQL JSON column.
    """

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )


# ============================================================
# BOOLEAN NORMALIZATION
# ============================================================

def _as_bool(value: Any) -> bool:
    """
    Convert common boolean representations into a Python bool.
    """

    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        return value.strip().lower() in {
            "true",
            "1",
            "yes",
        }

    return bool(value)


# ============================================================
# SAVE INCIDENT
# ============================================================

def save_incident(
    incident: Dict[str, Any],
) -> None:
    """
    Persist a fully enriched and risk-scored SentinelMesh
    incident into MySQL.

    The incident_id acts as the unique identifier.

    If the same incident is processed again, the existing
    incident is updated instead of creating a duplicate.
    """

    if not incident:
        raise ValueError(
            "Cannot persist an empty incident."
        )

    incident_id = incident.get(
        "incident_id"
    )

    if not incident_id:
        raise ValueError(
            "Cannot persist incident without incident_id."
        )

    initialize_database()

    risk_scoring = incident.get(
        "risk_scoring",
        {},
    )

    enrichment = incident.get(
        "enrichment",
        {},
    )

    risk_score = risk_scoring.get(
        "total_score"
    )

    risk_level = risk_scoring.get(
        "risk_level"
    )

    risk_model_version = risk_scoring.get(
        "model_version"
    )

    synthetic_evidence = _as_bool(
        enrichment.get(
            "synthetic_evidence",
            False,
        )
    )

    attribution_status = enrichment.get(
        "attribution_status"
    )

    connection = get_connection()
    cursor = connection.cursor()

    try:

        # ====================================================
        # MAIN INCIDENT
        # ====================================================

        cursor.execute(
            """
            INSERT INTO incidents (
                incident_id,
                timestamp,
                host,
                incident_type,
                severity,
                correlation_rule,
                rule_name,
                threat_profile,
                time_window_seconds,
                status,
                risk_score,
                risk_level,
                risk_model_version,
                synthetic_evidence,
                attribution_status,
                incident_json
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s
            )

            ON DUPLICATE KEY UPDATE

                timestamp = VALUES(timestamp),

                host = VALUES(host),

                incident_type =
                    VALUES(incident_type),

                severity =
                    VALUES(severity),

                correlation_rule =
                    VALUES(correlation_rule),

                rule_name =
                    VALUES(rule_name),

                threat_profile =
                    VALUES(threat_profile),

                time_window_seconds =
                    VALUES(time_window_seconds),

                status =
                    VALUES(status),

                risk_score =
                    VALUES(risk_score),

                risk_level =
                    VALUES(risk_level),

                risk_model_version =
                    VALUES(risk_model_version),

                synthetic_evidence =
                    VALUES(synthetic_evidence),

                attribution_status =
                    VALUES(attribution_status),

                incident_json =
                    VALUES(incident_json)
            """,
            (
                incident_id,
                incident.get("timestamp"),
                incident.get("host"),
                incident.get("incident_type"),
                incident.get("severity"),
                incident.get("correlation_rule"),
                incident.get("rule_name"),
                incident.get("threat_profile"),
                incident.get("time_window_seconds"),
                incident.get("status"),
                risk_score,
                risk_level,
                risk_model_version,
                synthetic_evidence,
                attribution_status,
                _json(incident),
            ),
        )

        # ====================================================
        # REMOVE OLD CHILD RECORDS
        # ====================================================

        cursor.execute(
            """
            DELETE FROM incident_evidence
            WHERE incident_id = %s
            """,
            (incident_id,),
        )

        cursor.execute(
            """
            DELETE FROM incident_techniques
            WHERE incident_id = %s
            """,
            (incident_id,),
        )

        cursor.execute(
            """
            DELETE FROM incident_entities
            WHERE incident_id = %s
            """,
            (incident_id,),
        )

        cursor.execute(
            """
            DELETE FROM incident_risk_factors
            WHERE incident_id = %s
            """,
            (incident_id,),
        )

        # ====================================================
        # EVIDENCE
        # ====================================================

        evidence_list = incident.get(
            "evidence",
            [],
        )

        for index, evidence in enumerate(
            evidence_list
        ):

            cursor.execute(
                """
                INSERT INTO incident_evidence (
                    incident_id,
                    evidence_index,
                    source,
                    rule_id,
                    rule_name,
                    severity,
                    source_record,
                    detection_id,
                    behavior_type,
                    evidence_json
                )
                VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s
                )
                """,
                (
                    incident_id,
                    index,
                    evidence.get("source"),
                    evidence.get("rule_id"),
                    evidence.get("rule_name"),
                    evidence.get("severity"),
                    (
                        str(
                            evidence.get(
                                "source_record"
                            )
                        )
                        if evidence.get(
                            "source_record"
                        ) is not None
                        else None
                    ),
                    evidence.get(
                        "detection_id"
                    ),
                    evidence.get(
                        "behavior_type"
                    ),
                    _json(evidence),
                ),
            )

        # ====================================================
        # MITRE TECHNIQUES
        # ====================================================

        mitre_context = incident.get(
            "mitre_context",
            {},
        )

        combined_techniques = (
            mitre_context.get(
                "combined_techniques",
                [],
            )
        )

        for technique in combined_techniques:

            technique_id = technique.get(
                "technique_id"
            )

            if not technique_id:
                continue

            technique_source = None

            # ------------------------------------------------
            # Check Windows Security techniques
            # ------------------------------------------------

            for windows_technique in (
                mitre_context.get(
                    "windows_techniques",
                    [],
                )
            ):

                if (
                    windows_technique.get(
                        "technique_id"
                    )
                    == technique_id
                ):
                    technique_source = (
                        "windows_security"
                    )
                    break

            # ------------------------------------------------
            # Check behavior techniques
            # ------------------------------------------------

            if technique_source is None:

                for behavior_technique in (
                    mitre_context.get(
                        "behavior_techniques",
                        [],
                    )
                ):

                    if (
                        behavior_technique.get(
                            "technique_id"
                        )
                        == technique_id
                    ):
                        technique_source = (
                            "behavior_telemetry"
                        )
                        break

            cursor.execute(
                """
                INSERT INTO incident_techniques (
                    incident_id,
                    technique_id,
                    technique_name,
                    tactic,
                    technique_source,
                    technique_json
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    incident_id,
                    technique_id,
                    technique.get(
                        "technique_name"
                    ),
                    technique.get(
                        "tactic"
                    ),
                    technique_source,
                    _json(technique),
                ),
            )

        # ====================================================
        # ENTITIES
        # ====================================================

        entities = incident.get(
            "entities",
            {},
        )

        if isinstance(
            entities,
            dict,
        ):

            for entity_type, values in (
                entities.items()
            ):

                if not isinstance(
                    values,
                    list,
                ):
                    continue

                for value in values:

                    # ----------------------------------------
                    # Entity represented as an object
                    # ----------------------------------------

                    if isinstance(
                        value,
                        dict,
                    ):

                        entity_value = (
                            value.get("value")
                            or value.get("hostname")
                            or value.get("username")
                            or value.get("process_name")
                            or value.get("ip")
                            or value.get("ip_address")
                        )

                    # ----------------------------------------
                    # Entity represented directly as a value
                    # ----------------------------------------

                    else:

                        entity_value = value

                    if entity_value is None:
                        continue

                    entity_value = str(
                        entity_value
                    ).strip()

                    if not entity_value:
                        continue

                    cursor.execute(
                        """
                        INSERT IGNORE INTO incident_entities (
                            incident_id,
                            entity_type,
                            entity_value
                        )
                        VALUES (
                            %s, %s, %s
                        )
                        """,
                        (
                            incident_id,
                            entity_type,
                            entity_value,
                        ),
                    )

        # ====================================================
        # RISK FACTORS
        # ====================================================

        factor_details = (
            risk_scoring.get(
                "factor_details",
                {},
            )
        )

        if isinstance(
            factor_details,
            dict,
        ):

            for factor_name, factor in (
                factor_details.items()
            ):

                if not isinstance(
                    factor,
                    dict,
                ):
                    continue

                cursor.execute(
                    """
                    INSERT INTO incident_risk_factors (
                        incident_id,
                        factor_name,
                        score,
                        maximum,
                        factor_json
                    )
                    VALUES (
                        %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        incident_id,
                        factor_name,
                        factor.get("score"),
                        factor.get("maximum"),
                        _json(factor),
                    ),
                )

        # ====================================================
        # COMMIT EVERYTHING
        # ====================================================

        connection.commit()

    except Exception:

        connection.rollback()

        raise

    finally:

        cursor.close()
        connection.close()


# ============================================================
# GET ONE INCIDENT
# ============================================================

def get_incident(
    incident_id: str,
) -> Optional[Dict[str, Any]]:
    """
    Retrieve one complete persisted incident using its ID.
    """

    initialize_database()

    connection = get_connection()

    cursor = connection.cursor(
        dictionary=True
    )

    try:

        cursor.execute(
            """
            SELECT incident_json
            FROM incidents
            WHERE incident_id = %s
            """,
            (incident_id,),
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return json.loads(
            row["incident_json"]
        )

    finally:

        cursor.close()
        connection.close()


# ============================================================
# LIST INCIDENTS
# ============================================================

def list_incidents(
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """
    Retrieve persisted incidents from newest to oldest.
    """

    initialize_database()

    limit = max(
        1,
        min(
            int(limit),
            1000,
        ),
    )

    connection = get_connection()

    cursor = connection.cursor(
        dictionary=True
    )

    try:

        cursor.execute(
            f"""
            SELECT incident_json
            FROM incidents
            ORDER BY timestamp DESC
            LIMIT {limit}
            """
        )

        rows = cursor.fetchall()

        return [
            json.loads(
                row["incident_json"]
            )
            for row in rows
        ]

    finally:

        cursor.close()
        connection.close()


# ============================================================
# DATABASE STATISTICS
# ============================================================

def get_database_stats() -> Dict[str, int]:
    """
    Return basic SentinelMesh database statistics.
    """

    initialize_database()

    connection = get_connection()

    cursor = connection.cursor()

    try:

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM incidents
            """
        )

        incident_count = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM incident_evidence
            """
        )

        evidence_count = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM incident_techniques
            """
        )

        technique_count = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM incident_entities
            """
        )

        entity_count = cursor.fetchone()[0]

        return {
            "incidents": incident_count,
            "evidence": evidence_count,
            "techniques": technique_count,
            "entities": entity_count,
        }

    finally:

        cursor.close()
        connection.close()


# ============================================================
# DIRECT DATABASE TEST
# ============================================================

if __name__ == "__main__":

    print(
        "Initializing SentinelMesh MySQL database..."
    )

    initialize_database()

    print(
        "MySQL database initialized successfully."
    )

    print(
        f"Database: {MYSQL_DATABASE}"
    )

    print(
        f"Host: {MYSQL_HOST}:{MYSQL_PORT}"
    )

    print(
        get_database_stats()
    )