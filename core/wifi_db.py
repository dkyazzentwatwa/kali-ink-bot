"""
Project Inkling - WiFi Database

SQLite database for WiFi targets, handshakes, deauth logs, and evil twin alerts.
Optimized for Raspberry Pi Zero 2W (WAL mode, limited history, efficient queries).
"""

import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class EncryptionType(str, Enum):
    """WiFi encryption types."""
    OPEN = "open"
    WEP = "wep"
    WPA = "wpa"
    WPA2 = "wpa2"
    WPA3 = "wpa3"
    UNKNOWN = "unknown"


class CaptureType(str, Enum):
    """Handshake capture types."""
    FOUR_WAY = "4way"
    PMKID = "pmkid"


@dataclass
class WiFiTarget:
    """WiFi access point target."""
    id: int
    bssid: str
    ssid: Optional[str]
    channel: int
    encryption: EncryptionType
    signal_max: int  # Best signal seen (dBm, negative)
    signal_last: int  # Most recent signal
    first_seen: float
    last_seen: float
    clients_seen: int = 0
    handshake_captured: bool = False
    pmkid_captured: bool = False
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "encryption": self.encryption.value,
            "signal_max": self.signal_max,
            "signal_last": self.signal_last,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "clients_seen": self.clients_seen,
            "handshake_captured": self.handshake_captured,
            "pmkid_captured": self.pmkid_captured,
            "notes": self.notes,
        }


@dataclass
class Handshake:
    """Captured WiFi handshake."""
    id: int
    target_id: int
    bssid: str
    ssid: Optional[str]
    capture_type: CaptureType
    file_path: str  # Path to .cap or .pcap file
    timestamp: float
    cracked: bool = False
    password: Optional[str] = None
    crack_time_sec: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "capture_type": self.capture_type.value,
            "file_path": self.file_path,
            "timestamp": self.timestamp,
            "cracked": self.cracked,
            "password": self.password if self.cracked else None,
            "crack_time_sec": self.crack_time_sec,
        }


@dataclass
class DeauthLog:
    """Deauth attempt log entry."""
    id: int
    target_id: int
    bssid: str
    client_mac: Optional[str]
    packets_sent: int
    success: bool  # Did handshake follow?
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "bssid": self.bssid,
            "client_mac": self.client_mac,
            "packets_sent": self.packets_sent,
            "success": self.success,
            "timestamp": self.timestamp,
        }


@dataclass
class EvilTwinAlert:
    """Evil twin detection alert."""
    id: int
    original_bssid: str
    rogue_bssid: str
    ssid: str
    timestamp: float
    dismissed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "original_bssid": self.original_bssid,
            "rogue_bssid": self.rogue_bssid,
            "ssid": self.ssid,
            "timestamp": self.timestamp,
            "dismissed": self.dismissed,
        }


@dataclass
class WiFiClient:
    """WiFi client associated with an AP."""
    id: int
    target_id: int
    mac_address: str
    first_seen: float
    last_seen: float
    packets: int = 0
    probes: str = ""  # JSON list of probed SSIDs

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "mac_address": self.mac_address,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "packets": self.packets,
            "probes": json.loads(self.probes) if self.probes else [],
        }


class WiFiDB:
    """
    WiFi hunting database manager.

    Uses SQLite with WAL mode for concurrent reads and writes.
    Automatically limits history to prevent unbounded growth.
    """

    MAX_TARGETS = 500  # Max WiFi targets to keep
    MAX_HANDSHAKES = 100  # Max handshakes to keep
    MAX_DEAUTH_LOGS = 1000  # Max deauth log entries
    MAX_CLIENTS = 2000  # Max client entries

    def __init__(self, db_path: str = "~/.inkling/wifi.db"):
        """Initialize database connection."""
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        with self._get_connection() as conn:
            # Enable WAL mode for better concurrent access
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")

            # WiFi targets table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS wifi_targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bssid TEXT UNIQUE NOT NULL,
                    ssid TEXT,
                    channel INTEGER NOT NULL DEFAULT 0,
                    encryption TEXT DEFAULT 'unknown',
                    signal_max INTEGER DEFAULT -100,
                    signal_last INTEGER DEFAULT -100,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    clients_seen INTEGER DEFAULT 0,
                    handshake_captured INTEGER DEFAULT 0,
                    pmkid_captured INTEGER DEFAULT 0,
                    notes TEXT DEFAULT ''
                )
            """)

            # Handshakes table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS handshakes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER REFERENCES wifi_targets(id) ON DELETE CASCADE,
                    bssid TEXT NOT NULL,
                    ssid TEXT,
                    capture_type TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    cracked INTEGER DEFAULT 0,
                    password TEXT,
                    crack_time_sec REAL
                )
            """)

            # Deauth logs table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS deauth_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER REFERENCES wifi_targets(id) ON DELETE CASCADE,
                    bssid TEXT NOT NULL,
                    client_mac TEXT,
                    packets_sent INTEGER NOT NULL,
                    success INTEGER DEFAULT 0,
                    timestamp REAL NOT NULL
                )
            """)

            # Evil twin alerts table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evil_twin_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_bssid TEXT NOT NULL,
                    rogue_bssid TEXT NOT NULL,
                    ssid TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    dismissed INTEGER DEFAULT 0
                )
            """)

            # WiFi clients table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS wifi_clients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER REFERENCES wifi_targets(id) ON DELETE CASCADE,
                    mac_address TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    packets INTEGER DEFAULT 0,
                    probes TEXT DEFAULT '[]',
                    UNIQUE(target_id, mac_address)
                )
            """)

            # Indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_targets_bssid ON wifi_targets(bssid)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_targets_ssid ON wifi_targets(ssid)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_targets_last_seen ON wifi_targets(last_seen DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_handshakes_target ON handshakes(target_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_deauth_target ON deauth_log(target_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_clients_target ON wifi_clients(target_id)")

            conn.commit()

    @contextmanager
    def _get_connection(self):
        """Get database connection with context management."""
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    # ========================================
    # WiFi Target Management
    # ========================================

    def upsert_target(
        self,
        bssid: str,
        ssid: Optional[str] = None,
        channel: int = 0,
        encryption: EncryptionType = EncryptionType.UNKNOWN,
        signal: int = -100,
    ) -> WiFiTarget:
        """
        Insert or update a WiFi target.

        If target exists (by BSSID), update last_seen and signal.
        """
        now = time.time()

        with self._get_connection() as conn:
            # Check if exists
            existing = conn.execute(
                "SELECT * FROM wifi_targets WHERE bssid = ?",
                (bssid.upper(),)
            ).fetchone()

            if existing:
                # Update existing
                new_signal_max = max(existing["signal_max"], signal)
                conn.execute(
                    """
                    UPDATE wifi_targets
                    SET ssid = COALESCE(?, ssid),
                        channel = CASE WHEN ? > 0 THEN ? ELSE channel END,
                        encryption = CASE WHEN ? != 'unknown' THEN ? ELSE encryption END,
                        signal_max = ?,
                        signal_last = ?,
                        last_seen = ?
                    WHERE id = ?
                    """,
                    (ssid, channel, channel, encryption.value, encryption.value,
                     new_signal_max, signal, now, existing["id"])
                )
                conn.commit()
                return self.get_target(existing["id"])
            else:
                # Insert new
                cursor = conn.execute(
                    """
                    INSERT INTO wifi_targets
                    (bssid, ssid, channel, encryption, signal_max, signal_last, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (bssid.upper(), ssid, channel, encryption.value, signal, signal, now, now)
                )
                conn.commit()

                # Prune if needed
                self._prune_targets(conn)

                return WiFiTarget(
                    id=cursor.lastrowid,
                    bssid=bssid.upper(),
                    ssid=ssid,
                    channel=channel,
                    encryption=encryption,
                    signal_max=signal,
                    signal_last=signal,
                    first_seen=now,
                    last_seen=now,
                )

    def get_target(self, target_id: int) -> Optional[WiFiTarget]:
        """Get a target by ID."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM wifi_targets WHERE id = ?",
                (target_id,)
            ).fetchone()

            if row:
                return self._row_to_target(row)
            return None

    def get_target_by_bssid(self, bssid: str) -> Optional[WiFiTarget]:
        """Get a target by BSSID."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM wifi_targets WHERE bssid = ?",
                (bssid.upper(),)
            ).fetchone()

            if row:
                return self._row_to_target(row)
            return None

    def list_targets(
        self,
        encryption: Optional[EncryptionType] = None,
        has_handshake: Optional[bool] = None,
        limit: int = 100,
        order_by: str = "last_seen",
    ) -> List[WiFiTarget]:
        """List WiFi targets with optional filters."""
        with self._get_connection() as conn:
            conditions = []
            values = []

            if encryption:
                conditions.append("encryption = ?")
                values.append(encryption.value)

            if has_handshake is not None:
                if has_handshake:
                    conditions.append("(handshake_captured = 1 OR pmkid_captured = 1)")
                else:
                    conditions.append("handshake_captured = 0 AND pmkid_captured = 0")

            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

            # Order by clause
            if order_by == "signal":
                order_clause = "ORDER BY signal_last DESC"
            elif order_by == "first_seen":
                order_clause = "ORDER BY first_seen DESC"
            else:
                order_clause = "ORDER BY last_seen DESC"

            values.append(limit)

            rows = conn.execute(
                f"SELECT * FROM wifi_targets {where_clause} {order_clause} LIMIT ?",
                values
            ).fetchall()

            return [self._row_to_target(row) for row in rows]

    def update_target(
        self,
        target_id: int,
        handshake_captured: Optional[bool] = None,
        pmkid_captured: Optional[bool] = None,
        clients_seen: Optional[int] = None,
        notes: Optional[str] = None,
    ) -> bool:
        """Update target fields."""
        updates = []
        values = []

        if handshake_captured is not None:
            updates.append("handshake_captured = ?")
            values.append(1 if handshake_captured else 0)
        if pmkid_captured is not None:
            updates.append("pmkid_captured = ?")
            values.append(1 if pmkid_captured else 0)
        if clients_seen is not None:
            updates.append("clients_seen = ?")
            values.append(clients_seen)
        if notes is not None:
            updates.append("notes = ?")
            values.append(notes)

        if not updates:
            return False

        values.append(target_id)

        with self._get_connection() as conn:
            cursor = conn.execute(
                f"UPDATE wifi_targets SET {', '.join(updates)} WHERE id = ?",
                values
            )
            conn.commit()
            return cursor.rowcount > 0

    def remove_target(self, target_id: int) -> bool:
        """Remove a target and all related data."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM wifi_targets WHERE id = ?",
                (target_id,)
            )
            conn.commit()
            return cursor.rowcount > 0

    def _prune_targets(self, conn: sqlite3.Connection) -> None:
        """Prune old targets to stay within limit."""
        conn.execute(
            """
            DELETE FROM wifi_targets WHERE id IN (
                SELECT id FROM wifi_targets
                WHERE handshake_captured = 0 AND pmkid_captured = 0
                ORDER BY last_seen DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (self.MAX_TARGETS,)
        )
        conn.commit()

    def _row_to_target(self, row: sqlite3.Row) -> WiFiTarget:
        """Convert database row to WiFiTarget object."""
        try:
            encryption = EncryptionType(row["encryption"])
        except ValueError:
            encryption = EncryptionType.UNKNOWN

        return WiFiTarget(
            id=row["id"],
            bssid=row["bssid"],
            ssid=row["ssid"],
            channel=row["channel"],
            encryption=encryption,
            signal_max=row["signal_max"],
            signal_last=row["signal_last"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            clients_seen=row["clients_seen"],
            handshake_captured=bool(row["handshake_captured"]),
            pmkid_captured=bool(row["pmkid_captured"]),
            notes=row["notes"],
        )

    # ========================================
    # Handshake Management
    # ========================================

    def save_handshake(
        self,
        target_id: int,
        bssid: str,
        capture_type: CaptureType,
        file_path: str,
        ssid: Optional[str] = None,
    ) -> Handshake:
        """Save a captured handshake."""
        now = time.time()

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO handshakes
                (target_id, bssid, ssid, capture_type, file_path, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (target_id, bssid.upper(), ssid, capture_type.value, file_path, now)
            )
            conn.commit()

            # Update target to mark capture
            if capture_type == CaptureType.PMKID:
                self.update_target(target_id, pmkid_captured=True)
            else:
                self.update_target(target_id, handshake_captured=True)

            # Prune old handshakes
            self._prune_handshakes(conn)

            return Handshake(
                id=cursor.lastrowid,
                target_id=target_id,
                bssid=bssid.upper(),
                ssid=ssid,
                capture_type=capture_type,
                file_path=file_path,
                timestamp=now,
            )

    def get_handshake(self, handshake_id: int) -> Optional[Handshake]:
        """Get a handshake by ID."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM handshakes WHERE id = ?",
                (handshake_id,)
            ).fetchone()

            if row:
                return self._row_to_handshake(row)
            return None

    def list_handshakes(
        self,
        target_id: Optional[int] = None,
        capture_type: Optional[CaptureType] = None,
        cracked: Optional[bool] = None,
        limit: int = 50,
    ) -> List[Handshake]:
        """List handshakes with optional filters."""
        with self._get_connection() as conn:
            conditions = []
            values = []

            if target_id is not None:
                conditions.append("target_id = ?")
                values.append(target_id)
            if capture_type:
                conditions.append("capture_type = ?")
                values.append(capture_type.value)
            if cracked is not None:
                conditions.append("cracked = ?")
                values.append(1 if cracked else 0)

            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            values.append(limit)

            rows = conn.execute(
                f"SELECT * FROM handshakes {where_clause} ORDER BY timestamp DESC LIMIT ?",
                values
            ).fetchall()

            return [self._row_to_handshake(row) for row in rows]

    def mark_handshake_cracked(
        self,
        handshake_id: int,
        password: str,
        crack_time_sec: Optional[float] = None,
    ) -> bool:
        """Mark a handshake as cracked."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE handshakes
                SET cracked = 1, password = ?, crack_time_sec = ?
                WHERE id = ?
                """,
                (password, crack_time_sec, handshake_id)
            )
            conn.commit()
            return cursor.rowcount > 0

    def _prune_handshakes(self, conn: sqlite3.Connection) -> None:
        """Prune old handshakes to stay within limit (keep cracked ones)."""
        conn.execute(
            """
            DELETE FROM handshakes WHERE id IN (
                SELECT id FROM handshakes
                WHERE cracked = 0
                ORDER BY timestamp DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (self.MAX_HANDSHAKES,)
        )
        conn.commit()

    def _row_to_handshake(self, row: sqlite3.Row) -> Handshake:
        """Convert database row to Handshake object."""
        try:
            capture_type = CaptureType(row["capture_type"])
        except ValueError:
            capture_type = CaptureType.FOUR_WAY

        return Handshake(
            id=row["id"],
            target_id=row["target_id"],
            bssid=row["bssid"],
            ssid=row["ssid"],
            capture_type=capture_type,
            file_path=row["file_path"],
            timestamp=row["timestamp"],
            cracked=bool(row["cracked"]),
            password=row["password"],
            crack_time_sec=row["crack_time_sec"],
        )

    # ========================================
    # Deauth Logging
    # ========================================

    def log_deauth(
        self,
        target_id: int,
        bssid: str,
        packets_sent: int,
        client_mac: Optional[str] = None,
        success: bool = False,
    ) -> DeauthLog:
        """Log a deauth attempt."""
        now = time.time()

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO deauth_log
                (target_id, bssid, client_mac, packets_sent, success, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (target_id, bssid.upper(), client_mac, packets_sent, 1 if success else 0, now)
            )
            conn.commit()

            # Prune old logs
            self._prune_deauth_logs(conn)

            return DeauthLog(
                id=cursor.lastrowid,
                target_id=target_id,
                bssid=bssid.upper(),
                client_mac=client_mac,
                packets_sent=packets_sent,
                success=success,
                timestamp=now,
            )

    def list_deauth_logs(
        self,
        target_id: Optional[int] = None,
        limit: int = 100,
    ) -> List[DeauthLog]:
        """List deauth logs."""
        with self._get_connection() as conn:
            if target_id is not None:
                rows = conn.execute(
                    "SELECT * FROM deauth_log WHERE target_id = ? ORDER BY timestamp DESC LIMIT ?",
                    (target_id, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM deauth_log ORDER BY timestamp DESC LIMIT ?",
                    (limit,)
                ).fetchall()

            return [self._row_to_deauth_log(row) for row in rows]

    def _prune_deauth_logs(self, conn: sqlite3.Connection) -> None:
        """Prune old deauth logs."""
        conn.execute(
            """
            DELETE FROM deauth_log WHERE id IN (
                SELECT id FROM deauth_log
                ORDER BY timestamp DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (self.MAX_DEAUTH_LOGS,)
        )
        conn.commit()

    def _row_to_deauth_log(self, row: sqlite3.Row) -> DeauthLog:
        """Convert database row to DeauthLog object."""
        return DeauthLog(
            id=row["id"],
            target_id=row["target_id"],
            bssid=row["bssid"],
            client_mac=row["client_mac"],
            packets_sent=row["packets_sent"],
            success=bool(row["success"]),
            timestamp=row["timestamp"],
        )

    # ========================================
    # Evil Twin Detection
    # ========================================

    def add_evil_twin_alert(
        self,
        original_bssid: str,
        rogue_bssid: str,
        ssid: str,
    ) -> EvilTwinAlert:
        """Add an evil twin detection alert."""
        now = time.time()

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO evil_twin_alerts
                (original_bssid, rogue_bssid, ssid, timestamp)
                VALUES (?, ?, ?, ?)
                """,
                (original_bssid.upper(), rogue_bssid.upper(), ssid, now)
            )
            conn.commit()

            return EvilTwinAlert(
                id=cursor.lastrowid,
                original_bssid=original_bssid.upper(),
                rogue_bssid=rogue_bssid.upper(),
                ssid=ssid,
                timestamp=now,
            )

    def list_evil_twin_alerts(
        self,
        dismissed: Optional[bool] = None,
        limit: int = 50,
    ) -> List[EvilTwinAlert]:
        """List evil twin alerts."""
        with self._get_connection() as conn:
            if dismissed is not None:
                rows = conn.execute(
                    "SELECT * FROM evil_twin_alerts WHERE dismissed = ? ORDER BY timestamp DESC LIMIT ?",
                    (1 if dismissed else 0, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM evil_twin_alerts ORDER BY timestamp DESC LIMIT ?",
                    (limit,)
                ).fetchall()

            return [self._row_to_evil_twin(row) for row in rows]

    def dismiss_evil_twin_alert(self, alert_id: int) -> bool:
        """Dismiss an evil twin alert."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "UPDATE evil_twin_alerts SET dismissed = 1 WHERE id = ?",
                (alert_id,)
            )
            conn.commit()
            return cursor.rowcount > 0

    def _row_to_evil_twin(self, row: sqlite3.Row) -> EvilTwinAlert:
        """Convert database row to EvilTwinAlert object."""
        return EvilTwinAlert(
            id=row["id"],
            original_bssid=row["original_bssid"],
            rogue_bssid=row["rogue_bssid"],
            ssid=row["ssid"],
            timestamp=row["timestamp"],
            dismissed=bool(row["dismissed"]),
        )

    # ========================================
    # WiFi Client Tracking
    # ========================================

    def upsert_client(
        self,
        target_id: int,
        mac_address: str,
        packets: int = 0,
        probes: Optional[List[str]] = None,
    ) -> WiFiClient:
        """Insert or update a WiFi client."""
        now = time.time()

        with self._get_connection() as conn:
            existing = conn.execute(
                "SELECT * FROM wifi_clients WHERE target_id = ? AND mac_address = ?",
                (target_id, mac_address.upper())
            ).fetchone()

            if existing:
                # Update existing
                new_packets = existing["packets"] + packets
                existing_probes = json.loads(existing["probes"]) if existing["probes"] else []
                if probes:
                    existing_probes.extend(p for p in probes if p not in existing_probes)

                conn.execute(
                    """
                    UPDATE wifi_clients
                    SET last_seen = ?, packets = ?, probes = ?
                    WHERE id = ?
                    """,
                    (now, new_packets, json.dumps(existing_probes), existing["id"])
                )
                conn.commit()
                return self._row_to_client(conn.execute(
                    "SELECT * FROM wifi_clients WHERE id = ?",
                    (existing["id"],)
                ).fetchone())
            else:
                # Insert new
                cursor = conn.execute(
                    """
                    INSERT INTO wifi_clients
                    (target_id, mac_address, first_seen, last_seen, packets, probes)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (target_id, mac_address.upper(), now, now, packets, json.dumps(probes or []))
                )
                conn.commit()

                # Update target clients_seen count
                conn.execute(
                    """
                    UPDATE wifi_targets SET clients_seen = (
                        SELECT COUNT(*) FROM wifi_clients WHERE target_id = ?
                    ) WHERE id = ?
                    """,
                    (target_id, target_id)
                )
                conn.commit()

                return WiFiClient(
                    id=cursor.lastrowid,
                    target_id=target_id,
                    mac_address=mac_address.upper(),
                    first_seen=now,
                    last_seen=now,
                    packets=packets,
                    probes=json.dumps(probes or []),
                )

    def list_clients(
        self,
        target_id: Optional[int] = None,
        limit: int = 100,
    ) -> List[WiFiClient]:
        """List WiFi clients."""
        with self._get_connection() as conn:
            if target_id is not None:
                rows = conn.execute(
                    "SELECT * FROM wifi_clients WHERE target_id = ? ORDER BY last_seen DESC LIMIT ?",
                    (target_id, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM wifi_clients ORDER BY last_seen DESC LIMIT ?",
                    (limit,)
                ).fetchall()

            return [self._row_to_client(row) for row in rows]

    def _row_to_client(self, row: sqlite3.Row) -> WiFiClient:
        """Convert database row to WiFiClient object."""
        return WiFiClient(
            id=row["id"],
            target_id=row["target_id"],
            mac_address=row["mac_address"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            packets=row["packets"],
            probes=row["probes"],
        )

    # ========================================
    # Statistics
    # ========================================

    def get_stats(self) -> Dict[str, Any]:
        """Get overall WiFi hunting statistics."""
        with self._get_connection() as conn:
            target_count = conn.execute("SELECT COUNT(*) FROM wifi_targets").fetchone()[0]
            handshake_count = conn.execute("SELECT COUNT(*) FROM handshakes").fetchone()[0]
            cracked_count = conn.execute("SELECT COUNT(*) FROM handshakes WHERE cracked = 1").fetchone()[0]
            deauth_count = conn.execute("SELECT COUNT(*) FROM deauth_log").fetchone()[0]
            client_count = conn.execute("SELECT COUNT(*) FROM wifi_clients").fetchone()[0]
            alert_count = conn.execute("SELECT COUNT(*) FROM evil_twin_alerts WHERE dismissed = 0").fetchone()[0]

            # Encryption breakdown
            enc_rows = conn.execute(
                "SELECT encryption, COUNT(*) as count FROM wifi_targets GROUP BY encryption"
            ).fetchall()
            encryption_counts = {row["encryption"]: row["count"] for row in enc_rows}

            # Handshakes today
            today_start = time.time() - 86400
            today_handshakes = conn.execute(
                "SELECT COUNT(*) FROM handshakes WHERE timestamp > ?",
                (today_start,)
            ).fetchone()[0]

            return {
                "targets": target_count,
                "handshakes": handshake_count,
                "handshakes_cracked": cracked_count,
                "handshakes_today": today_handshakes,
                "deauth_attempts": deauth_count,
                "clients_tracked": client_count,
                "evil_twin_alerts": alert_count,
                "encryption_breakdown": encryption_counts,
            }

    def close(self) -> None:
        """Close database connection (no-op for connection per operation)."""
        pass
