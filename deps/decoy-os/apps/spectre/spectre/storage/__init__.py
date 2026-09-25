from __future__ import annotations

import json
import os
import sqlite3
import time
from typing import Dict, List, Optional


class SpectreDB:
    """
    SQLite-backed persistence layer for Spectre HIDS.
    Stores events, alerts, and session threat scores.
    """

    def __init__(self, db_path: str = "spectre.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        cursor = self.conn.cursor()
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                event_type TEXT NOT NULL,
                proc_pid INTEGER NOT NULL,
                proc_name TEXT NOT NULL,
                detail TEXT,
                mitre TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                score INTEGER NOT NULL,
                chain_json TEXT,
                explanation TEXT,
                mitre TEXT
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                leader_pid INTEGER NOT NULL,
                leader_name TEXT NOT NULL,
                leader_ctime REAL NOT NULL,
                total_score INTEGER NOT NULL DEFAULT 0,
                last_updated REAL NOT NULL,
                UNIQUE(leader_pid, leader_ctime)
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_sessions_score ON sessions(total_score);
        """)
        self.conn.commit()

    def insert_event(
        self,
        event_type: str,
        proc_pid: int,
        proc_name: str,
        detail: str = "",
        mitre: str = "",
    ):
        """Insert a detected behavioral event."""
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO events (timestamp, event_type, proc_pid, proc_name, detail, mitre) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (time.time(), event_type, proc_pid, proc_name, detail, mitre),
        )
        self.conn.commit()
        return cursor.lastrowid

    def insert_alert(
        self,
        rule_id: str,
        rule_name: str,
        score: int,
        chain: list[dict],
        explanation: str,
        mitre: str = "",
    ):
        """Insert a high-severity threshold alert."""
        chain_json = json.dumps(chain, default=str)
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO alerts (timestamp, rule_id, rule_name, score, chain_json, explanation, mitre) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (time.time(), rule_id, rule_name, score, chain_json, explanation, mitre),
        )
        self.conn.commit()
        return cursor.lastrowid

    def upsert_session(
        self,
        leader_pid: int,
        leader_name: str,
        leader_ctime: float,
        total_score: int,
    ):
        """Insert or update a session threat score."""
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO sessions (leader_pid, leader_name, leader_ctime, total_score, last_updated) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(leader_pid, leader_ctime) DO UPDATE SET "
            "total_score = excluded.total_score, last_updated = excluded.last_updated",
            (leader_pid, leader_name, leader_ctime, total_score, time.time()),
        )
        self.conn.commit()

    def query_events(self, limit: int = 100, offset: int = 0) -> list[dict]:
        """Query events ordered by most recent first."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [dict(row) for row in cursor.fetchall()]

    def query_alerts(self, limit: int = 100, offset: int = 0) -> list[dict]:
        """Query alerts ordered by most recent first."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [dict(row) for row in cursor.fetchall()]

    def query_sessions(self, limit: int = 100, offset: int = 0) -> list[dict]:
        """Query session scores ordered by highest score first."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM sessions ORDER BY total_score DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_stats(self) -> dict:
        """Get summary statistics."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM events")
        event_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts")
        alert_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM sessions")
        session_count = cursor.fetchone()[0]
        return {
            "total_events": event_count,
            "total_alerts": alert_count,
            "total_sessions": session_count,
        }

    def close(self):
        """Close the database connection."""
        self.conn.close()
