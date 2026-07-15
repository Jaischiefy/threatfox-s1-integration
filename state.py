"""SQLite state management for tracking imported IOCs."""

import os
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from logger import get_logger

logger = get_logger("state")


class StateDatabase:
    """SQLite database for tracking IOC imports."""

    def __init__(self, db_path: str = "threatfox_s1.db"):
        """Initialize state database."""
        self.db_path = Path(db_path)
        self.conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database tables."""
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row

        # Enforce owner-only file permissions (0600) for security
        if self.db_path.exists():
            os.chmod(str(self.db_path), stat.S_IRUSR | stat.S_IWUSR)

        cursor = self.conn.cursor()

        # IOCs table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                external_id TEXT UNIQUE NOT NULL,
                threatfox_id TEXT,
                s1_uuid TEXT UNIQUE,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT NOT NULL,
                confidence INTEGER,
                threat_type TEXT,
                malware_family TEXT,
                valid_until TIMESTAMP,
                enabled BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_synced TIMESTAMP
            )
            """
        )

        # Import history table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS import_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source TEXT,
                iocs_fetched INTEGER,
                iocs_valid INTEGER,
                iocs_created INTEGER,
                iocs_updated INTEGER,
                iocs_failed INTEGER,
                duration_seconds FLOAT,
                error_message TEXT
            )
            """
        )

        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_external_id ON iocs(external_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_s1_uuid ON iocs(s1_uuid)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_type ON iocs(type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_source ON iocs(source)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_valid_until ON iocs(valid_until)")

        self.conn.commit()
        logger.info("State database initialized", db_path=str(self.db_path))

    def add_ioc(
        self,
        external_id: str,
        ioc_type: str,
        value: str,
        source: str,
        s1_uuid: Optional[str] = None,
        threat_type: Optional[str] = None,
        malware_family: Optional[str] = None,
        confidence: Optional[int] = None,
        valid_until: Optional[str] = None,
        threatfox_id: Optional[str] = None,
    ) -> bool:
        """Add or update an IOC in state."""
        cursor = self.conn.cursor()

        try:
            cursor.execute(
                """
                INSERT OR REPLACE INTO iocs
                (external_id, threatfox_id, s1_uuid, type, value, source, confidence,
                 threat_type, malware_family, valid_until, updated_at, last_synced)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (
                    external_id,
                    threatfox_id,
                    s1_uuid,
                    ioc_type,
                    value,
                    source,
                    confidence,
                    threat_type,
                    malware_family,
                    valid_until,
                ),
            )
            self.conn.commit()
            logger.debug("IOC added to state", external_id=external_id)
            return True
        except sqlite3.IntegrityError as e:
            logger.error("Failed to add IOC to state", external_id=external_id, error=str(e))
            return False

    def get_ioc(self, external_id: str) -> Optional[dict]:
        """Get IOC from state by external ID."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM iocs WHERE external_id = ?", (external_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def is_ioc_imported(self, external_id: str) -> bool:
        """Check if IOC is already imported and active."""
        ioc = self.get_ioc(external_id)
        if not ioc:
            return False

        # Check if valid_until is in the future
        if ioc["valid_until"]:
            valid_until = datetime.fromisoformat(ioc["valid_until"])
            if valid_until < datetime.now(timezone.utc):
                return False

        return ioc["enabled"]

    def get_iocs_by_source(self, source: str) -> list[dict]:
        """Get all IOCs from a specific source."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM iocs WHERE source = ? AND enabled = 1",
            (source,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_expired_iocs(self) -> list[dict]:
        """Get IOCs past their expiration date."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM iocs WHERE valid_until < CURRENT_TIMESTAMP AND enabled = 1"
        )
        return [dict(row) for row in cursor.fetchall()]

    def mark_ioc_expired(self, external_id: str) -> bool:
        """Mark an IOC as expired (disabled)."""
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "UPDATE iocs SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE external_id = ?",
                (external_id,),
            )
            self.conn.commit()
            logger.debug("IOC marked as expired", external_id=external_id)
            return True
        except Exception as e:
            logger.error("Failed to mark IOC as expired", external_id=external_id, error=str(e))
            return False

    def record_import(
        self,
        source: str,
        iocs_fetched: int,
        iocs_valid: int,
        iocs_created: int,
        iocs_updated: int,
        iocs_failed: int,
        duration_seconds: float,
        error_message: Optional[str] = None,
    ) -> bool:
        """Record import history."""
        cursor = self.conn.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO import_history
                (source, iocs_fetched, iocs_valid, iocs_created, iocs_updated,
                 iocs_failed, duration_seconds, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source,
                    iocs_fetched,
                    iocs_valid,
                    iocs_created,
                    iocs_updated,
                    iocs_failed,
                    duration_seconds,
                    error_message,
                ),
            )
            self.conn.commit()
            return True
        except Exception as e:
            logger.error("Failed to record import history", error=str(e))
            return False

    def get_last_import_time(self, source: str = "ThreatFox") -> Optional[str]:
        """Get timestamp of last successful import."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT run_timestamp FROM import_history WHERE source = ? ORDER BY run_timestamp DESC LIMIT 1",
            (source,),
        )
        row = cursor.fetchone()
        return dict(row)["run_timestamp"] if row else None

    def get_stats(self) -> dict:
        """Get database statistics."""
        cursor = self.conn.cursor()

        # Total IOCs
        cursor.execute("SELECT COUNT(*) as count FROM iocs WHERE enabled = 1")
        total = cursor.fetchone()["count"]

        # By source
        cursor.execute(
            "SELECT source, COUNT(*) as count FROM iocs WHERE enabled = 1 GROUP BY source"
        )
        by_source = {row["source"]: row["count"] for row in cursor.fetchall()}

        # By type
        cursor.execute(
            "SELECT type, COUNT(*) as count FROM iocs WHERE enabled = 1 GROUP BY type"
        )
        by_type = {row["type"]: row["count"] for row in cursor.fetchall()}

        # Expired
        cursor.execute("SELECT COUNT(*) as count FROM iocs WHERE valid_until < CURRENT_TIMESTAMP AND enabled = 1")
        expired = cursor.fetchone()["count"]

        # Last import
        cursor.execute(
            "SELECT run_timestamp FROM import_history ORDER BY run_timestamp DESC LIMIT 1"
        )
        last_import = cursor.fetchone()
        last_import_time = dict(last_import)["run_timestamp"] if last_import else None

        return {
            "total_active": total,
            "by_source": by_source,
            "by_type": by_type,
            "expired": expired,
            "last_import": last_import_time,
        }

    def close(self) -> None:
        """Close database connection."""
        if self.conn:
            self.conn.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
