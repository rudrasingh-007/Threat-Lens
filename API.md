# ThreatLens API

## Overview

- **Base URL:** `http://localhost:5000`
- **Auto-generated docs:** `http://localhost:5000/docs`
- **CORS:** Enabled for all origins, methods, and headers during local development (`allow_origins=["*"]`)

ThreatLens exposes a small FastAPI surface for health checks, graph retrieval, AI threat hypothesis generation, blast radius analysis, and attack-path discovery.

---

## GET /api/health
**Description:** Returns API status
**Parameters:** None
**Response:**
```json
{"status": "ok", "message": "ThreatLens API is running"}
```

---

## GET /api/graph
**Description:** Returns the full threat graph as nodes and relationships
**Parameters:** None
**Response:**
```json
{
	"nodes": [
		{
			"id": "FIN-DESK-042",
			"name": "FIN-DESK-042",
			"type": "Host",
			"status": "compromised",
			"severity_score": 9,
			"os": "Windows 11",
			"role": "Finance Workstation",
			"ip_address": "10.10.4.21",
			"department": "Finance",
			"privilege_level": "standard",
			"full_name": null,
			"country": null,
			"is_external": false,
			"filename": null,
			"filesize": null,
			"description": "Endpoint used as initial phishing foothold",
			"timestamp": "2026-04-30T09:10:00Z"
		}
	],
	"links": [
		{
			"source": "FIN-DESK-042",
			"target": "DC01",
			"type": "LATERAL_MOVEMENT",
			"timestamp": "2026-04-30T09:24:00Z",
			"technique_id": "T1021",
			"technique_name": "Remote Services"
		}
	]
}
```

Node fields returned by the API include: `id`, `name`, `type`, `status`, `severity_score`, `os`, `role`, `ip_address`, `department`, `privilege_level`, `full_name`, `country`, `is_external`, `filename`, `filesize`, `description`, and `timestamp`.

Link fields returned by the API include: `source`, `target`, `type`, `timestamp`, `technique_id`, and `technique_name`.

---

## GET /api/hypothesis
**Description:** Returns a real Gemini AI-generated threat report
**Parameters:** None
**Response:**
```json
{"hypothesis": "Initial access likely originated from a phishing payload delivered to a finance workstation, followed by credential access and lateral movement toward domain infrastructure."}
```

---

## GET /api/blast-radius/{node_id}
**Description:** Returns a BFS traversal of nodes reachable from the selected node up to 4 hops
**Parameters:**
- `node_id` - The starting node identifier
**Response:**
```json
{
	"source": "FIN-DESK-042",
	"reachable": [
		{
			"id": "DC01",
			"name": "DC01",
			"type": "Host",
			"status": "compromised",
			"depth": 2
		}
	],
	"summary": {
		"total": 1,
		"hosts": 1,
		"ips": 0,
		"hashes": 0,
		"users": 0
	}
}
```

The `reachable` array contains nodes discovered during traversal with their minimum depth from the source node.

---

## GET /api/attack-path/{source_id}/{target_id}
**Description:** Returns the shortest attack path between two nodes
**Parameters:**
- `source_id` - Origin node identifier
- `target_id` - Destination node identifier
**Response:**
```json
{
	"found": true,
	"source": "FIN-DESK-042",
	"target": "DC01",
	"hops": 2,
	"path_nodes": ["FIN-DESK-042", "HR-LAPTOP-07", "DC01"]
}
```

If no valid path exists, `found` is `false` and `path_nodes` may be omitted or null.

---

## Node Type Descriptions

- **Host** - Endpoints, servers, and infrastructure systems in the attack graph
- **User** - Human identities, accounts, or personas involved in the incident
- **Hash** - Credential artifacts such as password hashes or captured secrets
- **IP** - External or internal network addresses associated with activity

## Relationship Type Descriptions

- **LATERAL_MOVEMENT** - Movement from one host or account to another inside the environment
- **RAN** - A process or executable launched on a host
- **CONNECTED_TO** - A direct connection between two graph entities
- **LOGGED_INTO** - Authentication or session establishment on a system

