"""Seed ThreatLens Neo4j data for a simulated APT attack scenario."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List

from dotenv import load_dotenv

from utils.neo4j_client import run_query


load_dotenv()


HOSTS: List[Dict[str, Any]] = [
    {
        "id": "FIN-DESK-042",
        "name": "FIN-DESK-042",
        "type": "Host",
        "os": "Windows 10",
        "role": "Finance workstation",
        "ip_address": "192.168.1.42",
        "status": "malicious",
        "severity_score": 95,
        "timestamp": "2025-02-28T08:00:00Z",
    },
    {
        "id": "EXEC-WS-01",
        "name": "EXEC-WS-01",
        "type": "Host",
        "os": "Windows 11",
        
        "role": "Executive workstation",
        "ip_address": "192.168.1.11",
        "status": "malicious",
        "severity_score": 88,
        "timestamp": "2025-02-28T09:14:00Z",
    },
    {
        "id": "IT-DESK-118",
        "name": "IT-DESK-118",
        "type": "Host",
        "os": "Windows 10",
        "role": "IT workstation",
        "ip_address": "192.168.1.118",
        "status": "clean",
        "severity_score": 8,
        "timestamp": "2025-02-28T10:45:00Z",
    },
    {
        "id": "FIN-SRV-01",
        "name": "FIN-SRV-01",
        "type": "Host",
        "os": "Windows Server 2019",
        "role": "Finance file server",
        "ip_address": "192.168.1.50",
        "status": "clean",
        "severity_score": 12,
        "timestamp": "2025-02-28T11:20:00Z",
    },
    {
        "id": "DC01",
        "name": "DC01",
        "type": "Host",
        "os": "Windows Server 2022",
        "role": "Primary domain controller",
        "ip_address": "192.168.1.1",
        "status": "malicious",
        "severity_score": 98,
        "timestamp": "2025-02-28T13:00:00Z",
    },
    {
        "id": "DC02",
        "name": "DC02",
        "type": "Host",
        "os": "Windows Server 2022",
        "role": "Backup domain controller",
        "ip_address": "192.168.1.2",
        "status": "clean",
        "severity_score": 10,
        "timestamp": "2025-02-28T13:30:00Z",
    },
    {
        "id": "EXCHANGE01",
        "name": "EXCHANGE01",
        "type": "Host",
        "os": "Windows Server 2019",
        "role": "Mail server",
        "ip_address": "192.168.1.5",
        "status": "clean",
        "severity_score": 8,
        "timestamp": "2025-02-28T08:30:00Z",
    },
    {
        "id": "SHAREPOINT-SRV",
        "name": "SHAREPOINT-SRV",
        "type": "Host",
        "os": "Windows Server 2019",
        "role": "Intranet/docs server",
        "ip_address": "192.168.1.6",
        "status": "clean",
        "severity_score": 10,
        "timestamp": "2025-02-28T07:45:00Z",
    },
    {
        "id": "LEGAL-DESK-23",
        "name": "LEGAL-DESK-23",
        "type": "Host",
        "os": "Windows 10",
        "role": "Legal workstation",
        "ip_address": "192.168.1.23",
        "status": "clean",
        "severity_score": 5,
        "timestamp": "2025-02-28T07:50:00Z",
    },
    {
        "id": "HR-LAPTOP-07",
        "name": "HR-LAPTOP-07",
        "type": "Host",
        "os": "Windows 11",
        "role": "HR laptop",
        "ip_address": "192.168.1.77",
        "status": "malicious",
        "severity_score": 82,
        "timestamp": "2025-02-28T09:31:00Z",
    },
]


USERS: List[Dict[str, Any]] = [
    {
        "id": "jsmith",
        "name": "jsmith",
        "type": "User",
        "full_name": "John Smith",
        "department": "Finance",
        "privilege_level": "standard",
        "status": "malicious",
        "severity_score": 92,
        "timestamp": "2025-02-28T09:14:00Z",
    },
    {
        "id": "tlarson",
        "name": "tlarson",
        "type": "User",
        "full_name": "Tom Larson",
        "department": "Finance",
        "privilege_level": "standard",
        "status": "clean",
        "severity_score": 15,
        "timestamp": "2025-02-28T09:31:00Z",
    },
    {
        "id": "bwilliams",
        "name": "bwilliams",
        "type": "User",
        "full_name": "Beth Williams",
        "department": "IT Admin",
        "privilege_level": "admin",
        "status": "clean",
        "severity_score": 10,
        "timestamp": "2025-02-28T10:45:00Z",
    },
    {
        "id": "rsanchez",
        "name": "rsanchez",
        "type": "User",
        "full_name": "Rosa Sanchez",
        "department": "HR",
        "privilege_level": "standard",
        "status": "malicious",
        "severity_score": 80,
        "timestamp": "2025-02-28T09:31:00Z",
    },
    {
        "id": "mjohnson",
        "name": "mjohnson",
        "type": "User",
        "full_name": "Mark Johnson",
        "department": "Executive",
        "privilege_level": "high",
        "status": "clean",
        "severity_score": 8,
        "timestamp": "2025-02-28T11:20:00Z",
    },
    {
        "id": "akowalski",
        "name": "akowalski",
        "type": "User",
        "full_name": "Anna Kowalski",
        "department": "Legal",
        "privilege_level": "standard",
        "status": "clean",
        "severity_score": 8,
        "timestamp": "2025-02-28T07:52:00Z",
    },
    {
        "id": "dpatel",
        "name": "dpatel",
        "type": "User",
        "full_name": "Dev Patel",
        "department": "IT Admin",
        "privilege_level": "admin",
        "status": "clean",
        "severity_score": 12,
        "timestamp": "2025-02-28T07:55:00Z",
    },
    {
        "id": "kchen",
        "name": "kchen",
        "type": "User",
        "full_name": "Karen Chen",
        "department": "HR",
        "privilege_level": "standard",
        "status": "clean",
        "severity_score": 5,
        "timestamp": "2025-02-28T07:58:00Z",
    },
]


IPS: List[Dict[str, Any]] = [
    {
        "id": "185.220.101.45",
        "name": "185.220.101.45",
        "type": "IP",
        "country": "Russia",
        "is_external": True,
        "status": "malicious",
        "severity_score": 100,
        "timestamp": "2025-02-28T10:45:00Z",
    },
    {
        "id": "45.33.32.156",
        "name": "45.33.32.156",
        "type": "IP",
        "country": "Netherlands",
        "is_external": True,
        "status": "malicious",
        "severity_score": 95,
        "timestamp": "2025-02-28T16:00:00Z",
    },
    {
        "id": "91.108.4.200",
        "name": "91.108.4.200",
        "type": "IP",
        "country": "Ukraine",
        "is_external": True,
        "status": "malicious",
        "severity_score": 85,
        "timestamp": "2025-02-28T09:14:00Z",
    },
    {
        "id": "192.168.1.10",
        "name": "192.168.1.10",
        "type": "IP",
        "country": "Internal",
        "is_external": False,
        "status": "clean",
        "severity_score": 5,
        "timestamp": "2025-02-28T08:00:00Z",
    },
    {
        "id": "192.168.1.20",
        "name": "192.168.1.20",
        "type": "IP",
        "country": "Internal",
        "is_external": False,
        "status": "clean",
        "severity_score": 5,
        "timestamp": "2025-02-28T08:00:00Z",
    },
    {
        "id": "8.8.8.8",
        "name": "8.8.8.8",
        "type": "IP",
        "country": "United States",
        "is_external": True,
        "status": "clean",
        "severity_score": 0,
        "timestamp": "2025-02-28T08:00:00Z",
    },
    {
        "id": "13.107.42.14",
        "name": "13.107.42.14",
        "type": "IP",
        "country": "United States",
        "is_external": True,
        "status": "clean",
        "severity_score": 0,
        "timestamp": "2025-02-28T08:00:00Z",
    },
    {
        "id": "151.101.1.140",
        "name": "151.101.1.140",
        "type": "IP",
        "country": "United States",
        "is_external": True,
        "status": "clean",
        "severity_score": 0,
        "timestamp": "2025-02-28T08:00:00Z",
    },
]


HASHES: List[Dict[str, Any]] = [
    {
        "id": "HASH-001",
        "name": "HASH-001",
        "type": "Hash",
        "filename": "invoice_Q1_2025.exe",
        "filesize": 245760,
        "description": "Emotet Loader — arrives as fake invoice",
        "status": "malicious",
        "severity_score": 98,
        "timestamp": "2025-02-28T09:14:00Z",
    },
    {
        "id": "HASH-002",
        "name": "HASH-002",
        "type": "Hash",
        "filename": "svchost32.exe",
        "filesize": 184320,
        "description": "Cobalt Strike Beacon — disguised as system process",
        "status": "malicious",
        "severity_score": 95,
        "timestamp": "2025-02-28T10:45:00Z",
    },
    {
        "id": "HASH-003",
        "name": "HASH-003",
        "type": "Hash",
        "filename": "mimikatz.exe",
        "filesize": 98304,
        "description": "Mimikatz — credential harvesting tool dumps LSASS",
        "status": "malicious",
        "severity_score": 100,
        "timestamp": "2025-02-28T13:00:00Z",
    },
    {
        "id": "HASH-004",
        "name": "HASH-004",
        "type": "Hash",
        "filename": "powershell_empire.ps1",
        "filesize": 32768,
        "description": "PowerShell Empire Stager",
        "status": "malicious",
        "severity_score": 88,
        "timestamp": "2025-02-28T11:20:00Z",
    },
    {
        "id": "HASH-005",
        "name": "HASH-005",
        "type": "Hash",
        "filename": "chrome_update.exe",
        "filesize": 196608,
        "description": "Second phishing payload for HR entry point",
        "status": "malicious",
        "severity_score": 82,
        "timestamp": "2025-02-28T09:31:00Z",
    },
    {
        "id": "HASH-006",
        "name": "HASH-006",
        "type": "Hash",
        "filename": "onedrive_sync.exe",
        "filesize": 163840,
        "description": "Persistence mechanism disguised as OneDrive",
        "status": "suspicious",
        "severity_score": 70,
        "timestamp": "2025-02-28T14:30:00Z",
    },
    {
        "id": "HASH-007",
        "name": "HASH-007",
        "type": "Hash",
        "filename": "Teams.exe",
        "filesize": 512000,
        "description": "Microsoft Teams legitimate binary",
        "status": "clean",
        "severity_score": 0,
        "timestamp": "2025-02-28T07:45:00Z",
    },
    {
        "id": "HASH-008",
        "name": "HASH-008",
        "type": "Hash",
        "filename": "chrome.exe",
        "filesize": 487424,
        "description": "Google Chrome legitimate binary",
        "status": "clean",
        "severity_score": 0,
        "timestamp": "2025-02-28T07:48:00Z",
    },
    {
        "id": "HASH-009",
        "name": "HASH-009",
        "type": "Hash",
        "filename": "AcroRd32.exe",
        "filesize": 409600,
        "description": "Adobe Reader legitimate binary",
        "status": "clean",
        "severity_score": 0,
        "timestamp": "2025-02-28T07:51:00Z",
    },
    {
        "id": "HASH-010",
        "name": "HASH-010",
        "type": "Hash",
        "filename": "7zFM.exe",
        "filesize": 204800,
        "description": "7-Zip legitimate binary",
        "status": "clean",
        "severity_score": 0,
        "timestamp": "2025-02-28T07:54:00Z",
    },
]


LOGGED_INTO = [
    {"from_id": "jsmith", "to_id": "FIN-DESK-042", "timestamp": "2025-02-28T08:55:00Z"},
    {
        "from_id": "jsmith",
        "to_id": "DC01",
        "timestamp": "2025-02-28T13:00:00Z",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
    },
    {"from_id": "tlarson", "to_id": "FIN-DESK-042", "timestamp": "2025-02-28T09:31:00Z"},
    {"from_id": "tlarson", "to_id": "FIN-SRV-01", "timestamp": "2025-02-28T11:20:00Z"},
    {"from_id": "bwilliams", "to_id": "IT-DESK-118", "timestamp": "2025-02-28T10:45:00Z"},
    {"from_id": "rsanchez", "to_id": "HR-LAPTOP-07", "timestamp": "2025-02-28T08:45:00Z"},
    {"from_id": "mjohnson", "to_id": "EXEC-WS-01", "timestamp": "2025-02-28T09:14:00Z"},
    {"from_id": "akowalski", "to_id": "LEGAL-DESK-23", "timestamp": "2025-02-28T07:52:00Z"},
    {"from_id": "dpatel", "to_id": "IT-DESK-118", "timestamp": "2025-02-28T07:55:00Z"},
    {"from_id": "kchen", "to_id": "HR-LAPTOP-07", "timestamp": "2025-02-28T07:58:00Z"},
]


RAN = [
    {
        "from_id": "FIN-DESK-042",
        "to_id": "HASH-001",
        "timestamp": "2025-02-28T09:14:00Z",
        "technique_id": "T1204",
        "technique_name": "User Execution",
    },
    {
        "from_id": "FIN-DESK-042",
        "to_id": "HASH-002",
        "timestamp": "2025-02-28T10:45:00Z",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
    },
    {
        "from_id": "DC01",
        "to_id": "HASH-003",
        "timestamp": "2025-02-28T13:00:00Z",
        "technique_id": "T1003",
        "technique_name": "Credential Dumping",
    },
    {
        "from_id": "FIN-SRV-01",
        "to_id": "HASH-004",
        "timestamp": "2025-02-28T11:20:00Z",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
    },
    {
        "from_id": "HR-LAPTOP-07",
        "to_id": "HASH-005",
        "timestamp": "2025-02-28T09:31:00Z",
        "technique_id": "T1204",
        "technique_name": "User Execution",
    },
    {
        "from_id": "EXEC-WS-01",
        "to_id": "HASH-002",
        "timestamp": "2025-02-28T10:45:00Z",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
    },
    {
        "from_id": "EXEC-WS-01",
        "to_id": "HASH-006",
        "timestamp": "2025-02-28T14:30:00Z",
        "technique_id": "T1547",
        "technique_name": "Boot or Logon Autostart Execution",
    },
    {"from_id": "IT-DESK-118", "to_id": "HASH-007", "timestamp": "2025-02-28T08:30:00Z"},
    {"from_id": "LEGAL-DESK-23", "to_id": "HASH-008", "timestamp": "2025-02-28T08:00:00Z"},
    {"from_id": "HR-LAPTOP-07", "to_id": "HASH-009", "timestamp": "2025-02-28T08:00:00Z"},
]


CONNECTED_TO = [
    {
        "from_id": "FIN-DESK-042",
        "to_id": "185.220.101.45",
        "timestamp": "2025-02-28T10:45:00Z",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
    },
    {
        "from_id": "FIN-DESK-042",
        "to_id": "91.108.4.200",
        "timestamp": "2025-02-28T09:14:00Z",
        "technique_id": "T1566",
        "technique_name": "Phishing",
    },
    {
        "from_id": "EXEC-WS-01",
        "to_id": "185.220.101.45",
        "timestamp": "2025-02-28T11:20:00Z",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
    },
    {
        "from_id": "DC01",
        "to_id": "45.33.32.156",
        "timestamp": "2025-02-28T16:00:00Z",
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
    },
    {
        "from_id": "HR-LAPTOP-07",
        "to_id": "91.108.4.200",
        "timestamp": "2025-02-28T09:31:00Z",
        "technique_id": "T1566",
        "technique_name": "Phishing",
    },
    {
        "from_id": "HR-LAPTOP-07",
        "to_id": "185.220.101.45",
        "timestamp": "2025-02-28T11:00:00Z",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
    },
    {"from_id": "LEGAL-DESK-23", "to_id": "8.8.8.8", "timestamp": "2025-02-28T07:50:00Z"},
    {"from_id": "IT-DESK-118", "to_id": "13.107.42.14", "timestamp": "2025-02-28T07:55:00Z"},
    {"from_id": "HR-LAPTOP-07", "to_id": "151.101.1.140", "timestamp": "2025-02-28T07:48:00Z"},
]


LATERAL_MOVEMENT = [
    {
        "from_id": "FIN-DESK-042",
        "to_id": "FIN-SRV-01",
        "timestamp": "2025-02-28T11:20:00Z",
        "technique_id": "T1021",
        "technique_name": "Remote Services",
    },
    {
        "from_id": "FIN-DESK-042",
        "to_id": "EXEC-WS-01",
        "timestamp": "2025-02-28T11:45:00Z",
        "technique_id": "T1021",
        "technique_name": "Remote Services",
    },
    {
        "from_id": "EXEC-WS-01",
        "to_id": "DC01",
        "timestamp": "2025-02-28T13:00:00Z",
        "technique_id": "T1021",
        "technique_name": "Remote Services",
    },
    {
        "from_id": "DC01",
        "to_id": "DC02",
        "timestamp": "2025-02-28T13:30:00Z",
        "technique_id": "T1021",
        "technique_name": "Remote Services",
    },
    {
        "from_id": "HR-LAPTOP-07",
        "to_id": "EXCHANGE01",
        "timestamp": "2025-02-28T12:00:00Z",
        "technique_id": "T1021",
        "technique_name": "Remote Services",
    },
    {
        "from_id": "FIN-SRV-01",
        "to_id": "SHAREPOINT-SRV",
        "timestamp": "2025-02-28T14:00:00Z",
        "technique_id": "T1021",
        "technique_name": "Remote Services",
    },
]


def seed_nodes(label: str, rows: Iterable[Dict[str, Any]], fields: List[str]) -> None:
    property_lines = [f"        {field}: row.{field}" for field in fields]
    query = "\n".join(
        [
            "UNWIND $rows AS row",
            f"CREATE (n:{label} {{",
            ",\n".join(property_lines),
            "})",
        ]
    )
    run_query(query, {"rows": list(rows)})


def seed_relationships(label: str, from_label: str, to_label: str, rows: Iterable[Dict[str, Any]]) -> None:
    query = f"""
    UNWIND $rows AS row
    MATCH (from:{from_label} {{id: row.from_id}})
    MATCH (to:{to_label} {{id: row.to_id}})
    CREATE (from)-[r:{label} {{
        timestamp: row.timestamp,
        technique_id: row.technique_id,
        technique_name: row.technique_name
    }}]->(to)
    """
    run_query(query, {"rows": list(rows)})


def clear_database() -> None:
    run_query("MATCH (n) DETACH DELETE n")


def print_summary() -> None:
    node_result = run_query("MATCH (n) RETURN count(n) AS nodes")
    relationship_result = run_query("MATCH ()-[r]->() RETURN count(r) AS relationships")
    print(f"Nodes created: {node_result[0]['nodes']}")
    print(f"Relationships created: {relationship_result[0]['relationships']}")


def main() -> None:
    clear_database()

    seed_nodes("Host", HOSTS, ["id", "name", "type", "os", "role", "ip_address", "status", "severity_score", "timestamp"])
    seed_nodes("User", USERS, ["id", "name", "type", "full_name", "department", "privilege_level", "status", "severity_score", "timestamp"])
    seed_nodes("IP", IPS, ["id", "name", "type", "country", "is_external", "status", "severity_score", "timestamp"])
    seed_nodes("Hash", HASHES, ["id", "name", "type", "filename", "filesize", "description", "status", "severity_score", "timestamp"])

    seed_relationships("LOGGED_INTO", "User", "Host", LOGGED_INTO)
    seed_relationships("RAN", "Host", "Hash", RAN)
    seed_relationships("CONNECTED_TO", "Host", "IP", CONNECTED_TO)
    seed_relationships("LATERAL_MOVEMENT", "Host", "Host", LATERAL_MOVEMENT)

    print_summary()


if __name__ == "__main__":
    main()