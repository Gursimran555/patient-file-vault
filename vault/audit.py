"""Tamper-evident access log.

Every access decision, allowed or denied, gets a row. Each row carries
HMAC(audit_key, previous_mac || row), so editing, deleting or reordering any
row breaks every MAC after it. verify() walks the chain and reports the first
broken row.

Limitation: deleting rows from the *end* leaves a valid shorter chain. To catch
that, export the latest (seq, mac) somewhere the database admin can't write,
e.g. a SIEM, and compare it with head().
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, db, key: bytes, clock=time.time):
        self.db = db
        self.key = key
        self.clock = clock

    def _mac(self, prev: str, entry: dict) -> str:
        msg = prev.encode() + json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self.key, msg, hashlib.sha256).hexdigest()

    def head(self) -> tuple[int, str]:
        row = self.db.execute("SELECT seq, mac FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return (row[0], row[1]) if row else (0, GENESIS)

    def record(self, actor: str, action: str, target: str, outcome: str) -> None:
        seq, prev = self.head()
        entry = {"seq": seq + 1, "ts": round(self.clock(), 3), "actor": actor,
                 "action": action, "target": target, "outcome": outcome}
        self.db.execute(
            "INSERT INTO audit (seq, ts, actor, action, target, outcome, mac) "
            "VALUES (:seq, :ts, :actor, :action, :target, :outcome, :mac)",
            {**entry, "mac": self._mac(prev, entry)})

    def verify(self) -> tuple[bool, int | None]:
        """(True, None) if intact, else (False, first bad seq)."""
        prev, expected_seq = GENESIS, 1
        for seq, ts, actor, action, target, outcome, mac in self.db.execute(
                "SELECT seq, ts, actor, action, target, outcome, mac FROM audit ORDER BY seq"):
            entry = {"seq": seq, "ts": ts, "actor": actor, "action": action,
                     "target": target, "outcome": outcome}
            if seq != expected_seq or not hmac.compare_digest(self._mac(prev, entry), mac):
                return False, expected_seq
            prev, expected_seq = mac, seq + 1
        return True, None

    def entries(self, target: str | None = None) -> list[dict]:
        sql = "SELECT seq, ts, actor, action, target, outcome FROM audit"
        args: tuple = ()
        if target:
            sql += " WHERE target = ?"
            args = (target,)
        cols = ("seq", "ts", "actor", "action", "target", "outcome")
        return [dict(zip(cols, r)) for r in self.db.execute(sql + " ORDER BY seq", args)]
