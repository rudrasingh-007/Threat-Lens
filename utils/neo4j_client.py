"""Neo4j client utilities for ThreatLens.

Functions:
- get_driver() -> returns a connected Neo4j driver
- close_driver(driver) -> closes the driver
- run_query(query, parameters=None) -> runs a Cypher query and returns list[dict]

This module reads NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD from a .env file.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from neo4j import GraphDatabase


# Load .env at import time so environment variables are available.
load_dotenv()


def get_driver() -> GraphDatabase.driver:
    """Create and return a connected Neo4j driver instance.

    Expects `NEO4J_URI`, `NEO4J_USERNAME`, and `NEO4J_PASSWORD` to be set in the environment
    (loaded from a .env file).
    """
    uri = os.getenv("NEO4J_URI")
    user = os.getenv("NEO4J_USERNAME")
    password = os.getenv("NEO4J_PASSWORD")

    if not uri or not user or not password:
        raise RuntimeError(
            "NEO4J_URI, NEO4J_USERNAME, and NEO4J_PASSWORD must be set in the environment"
        )

    driver = GraphDatabase.driver(uri, auth=(user, password))
    return driver


def close_driver(driver) -> None:
    """Close the given Neo4j driver instance."""
    try:
        driver.close()
    except Exception:
        # swallow exceptions on close to avoid masking earlier errors
        pass


def run_query(query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Run a Cypher query and return results as a list of dictionaries.

    This function opens a session, runs the query with optional parameters,
    collects the results, and closes resources.
    """
    driver = get_driver()
    try:
        with driver.session() as session:
            result = session.run(query, parameters or {})
            records = [record.data() for record in result]
            return records
    finally:
        close_driver(driver)


if __name__ == "__main__":
    # Simple smoke test: run RETURN 1 AS test and print the result.
    try:
        results = run_query("RETURN 1 AS test")
        print("Connection test result:", results)
    except Exception as exc:
        print("Neo4j connection test failed:", exc)