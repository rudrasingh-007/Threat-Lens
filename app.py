"""FastAPI backend for ThreatLens."""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from utils.gemini_client import generate_hypothesis
from utils.neo4j_client import run_query


load_dotenv()

app = FastAPI(
    title="ThreatLens API",
    description="Cybersecurity threat visualization and analysis API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class HealthResponse(BaseModel):
    status: str
    message: str


class GraphNode(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    type: Optional[str] = None
    status: Optional[str] = None
    severity_score: Optional[int] = None
    os: Optional[str] = None
    role: Optional[str] = None
    ip_address: Optional[str] = None
    department: Optional[str] = None
    privilege_level: Optional[str] = None
    full_name: Optional[str] = None
    country: Optional[str] = None
    is_external: Optional[bool] = None
    filename: Optional[str] = None
    filesize: Optional[int] = None
    description: Optional[str] = None
    timestamp: Optional[str] = None


class GraphLink(BaseModel):
    source: Optional[str] = None
    target: Optional[str] = None
    type: Optional[str] = None
    timestamp: Optional[str] = None
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None


class GraphResponse(BaseModel):
    nodes: List[GraphNode]
    links: List[GraphLink]


class HypothesisResponse(BaseModel):
    hypothesis: str


class BlastRadiusItem(BaseModel):
    id: str
    name: Optional[str] = None
    type: Optional[str] = None
    status: Optional[str] = None
    depth: int


class BlastRadiusSummary(BaseModel):
    total: int
    hosts: int
    ips: int
    hashes: int
    users: int


class BlastRadiusResponse(BaseModel):
    source: str
    reachable: List[BlastRadiusItem]
    summary: BlastRadiusSummary


class AttackPathResponse(BaseModel):
    found: bool
    source: str
    target: str
    hops: Optional[int] = None
    path_nodes: Optional[List[str]] = None


def _count_types(items: List[BlastRadiusItem]) -> BlastRadiusSummary:
    counts = Counter((item.type or "").lower() for item in items)
    return BlastRadiusSummary(
        total=len(items),
        hosts=counts.get("host", 0),
        ips=counts.get("ip", 0),
        hashes=counts.get("hash", 0),
        users=counts.get("user", 0),
    )


@app.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", message="ThreatLens API is running")


@app.get("/api/graph", response_model=GraphResponse)
def get_graph() -> GraphResponse:
    nodes_query = (
        "MATCH (n) RETURN n.id AS id, n.name AS name, n.type AS type, n.status AS status, "
        "n.severity_score AS severity_score, n.os AS os, n.role AS role, n.ip_address AS ip_address, "
        "n.department AS department, n.privilege_level AS privilege_level, n.full_name AS full_name, "
        "n.country AS country, n.is_external AS is_external, n.filename AS filename, n.filesize AS filesize, "
        "n.description AS description, n.timestamp AS timestamp"
    )

    links_query = (
        "MATCH (n)-[r]->(m) RETURN n.id AS source, m.id AS target, type(r) AS type, r.timestamp AS timestamp, "
        "r.technique_id AS technique_id, r.technique_name AS technique_name"
    )

    nodes = [GraphNode(**row) for row in run_query(nodes_query)]
    links = [GraphLink(**row) for row in run_query(links_query)]
    return GraphResponse(nodes=nodes, links=links)


@app.get("/api/hypothesis", response_model=HypothesisResponse)
def hypothesis() -> HypothesisResponse:
    nodes_query = "MATCH (n) WHERE n.status IN ['malicious', 'suspicious'] RETURN n.name AS name, n.type AS type, n.status AS status, n.severity_score AS severity_score, n.role AS role, n.department AS department, n.description AS description"
    links_query = "MATCH (n)-[r]->(m) WHERE n.status IN ['malicious', 'suspicious'] OR m.status IN ['malicious', 'suspicious'] RETURN n.name AS source, m.name AS target, type(r) AS relationship, r.technique_id AS technique_id, r.technique_name AS technique_name"
    
    nodes = run_query(nodes_query)
    links = run_query(links_query)
    
    graph_summary = f"THREAT NODES:\n"
    for node in nodes:
        graph_summary += f"- {node.get('name')} ({node.get('type')}) — Status: {node.get('status')}, Severity: {node.get('severity_score')}"
        if node.get('role'): graph_summary += f", Role: {node.get('role')}"
        if node.get('department'): graph_summary += f", Dept: {node.get('department')}"
        if node.get('description'): graph_summary += f", Description: {node.get('description')}"
        graph_summary += "\n"
    
    graph_summary += f"\nTHREAT RELATIONSHIPS:\n"
    for link in links:
        graph_summary += f"- {link.get('source')} → {link.get('target')} via {link.get('relationship')}"
        if link.get('technique_id'): graph_summary += f" ({link.get('technique_id')}: {link.get('technique_name')})"
        graph_summary += "\n"
    
    hypothesis_text = generate_hypothesis(graph_summary)
    return HypothesisResponse(hypothesis=hypothesis_text)


@app.get("/api/blast-radius/{node_id}", response_model=BlastRadiusResponse)
def blast_radius(node_id: str) -> BlastRadiusResponse:
    query = (
        "MATCH path = (start {id: $node_id})-[*1..4]->(reachable) "
        "RETURN reachable.id AS id, reachable.name AS name, reachable.type AS type, reachable.status AS status, "
        "length(path) AS depth"
    )

    results = run_query(query, {"node_id": node_id})

    reachable_by_id: Dict[str, BlastRadiusItem] = {}
    for row in results:
        reachable_id = row.get("id")
        if not reachable_id:
            continue

        depth = row.get("depth")
        if depth is None:
            continue

        item = BlastRadiusItem(
            id=reachable_id,
            name=row.get("name"),
            type=row.get("type"),
            status=row.get("status"),
            depth=depth,
        )

        current = reachable_by_id.get(reachable_id)
        if current is None or item.depth < current.depth:
            reachable_by_id[reachable_id] = item

    reachable = list(reachable_by_id.values())
    return BlastRadiusResponse(
        source=node_id,
        reachable=reachable,
        summary=_count_types(reachable),
    )


@app.get("/api/attack-path/{source_id}/{target_id}", response_model=AttackPathResponse)
def attack_path(source_id: str, target_id: str) -> AttackPathResponse:
    query = (
        "MATCH (start {id: $source_id}), (end {id: $target_id}) "
        "MATCH path = shortestPath((start)-[*..10]->(end)) "
        "RETURN [node in nodes(path) | node.id] AS path_nodes, length(path) AS hops"
    )

    results = run_query(query, {"source_id": source_id, "target_id": target_id})
    if not results:
        return AttackPathResponse(found=False, source=source_id, target=target_id)

    row = results[0]
    path_nodes = row.get("path_nodes")
    if not path_nodes:
        return AttackPathResponse(found=False, source=source_id, target=target_id)

    return AttackPathResponse(
        found=True,
        source=source_id,
        target=target_id,
        hops=row.get("hops"),
        path_nodes=path_nodes,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=5000, reload=True)