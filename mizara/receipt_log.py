from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any


@dataclass
class QueuedReceipt:
    receipt_id: str
    payload: dict[str, Any]


class ReceiptLog:
    """
    Write-ahead log for receipts awaiting delivery to the hosted API. A
    receipt is appended as "pending" before a flush is attempted and
    appended again as "ack" once the server confirms it. If the process
    crashes between those two writes, load_unacked() on the next startup
    returns it so it can be retried -- a receipt is never silently lost
    to a crash between the decision and the network flush.
    """

    def __init__(self, path: str) -> None:
        self._path = path

    def append_pending(self, entry: QueuedReceipt) -> None:
        self._append_line({"type": "pending", "receiptId": entry.receipt_id, "payload": entry.payload})

    def append_ack(self, receipt_id: str) -> None:
        self._append_line({"type": "ack", "receiptId": receipt_id})

    def load_unacked(self) -> list[QueuedReceipt]:
        if not os.path.exists(self._path):
            return []

        pending: dict[str, QueuedReceipt] = {}
        acked: set[str] = set()

        for entry in self._read_lines():
            if entry["type"] == "pending":
                pending[entry["receiptId"]] = QueuedReceipt(receipt_id=entry["receiptId"], payload=entry["payload"])
            else:
                acked.add(entry["receiptId"])

        return [entry for rid, entry in pending.items() if rid not in acked]

    def compact(self) -> None:
        unacked = self.load_unacked()
        lines = [json.dumps({"type": "pending", "receiptId": e.receipt_id, "payload": e.payload}) for e in unacked]
        with open(self._path, "w") as f:
            f.write(("\n".join(lines) + "\n") if lines else "")

    def _append_line(self, entry: dict[str, Any]) -> None:
        with open(self._path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def _read_lines(self) -> list[dict[str, Any]]:
        with open(self._path, "r") as f:
            return [json.loads(line) for line in f if line.strip()]
