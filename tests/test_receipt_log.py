from __future__ import annotations

import os
import tempfile

import pytest

from mizara.receipt_log import QueuedReceipt, ReceiptLog


@pytest.fixture
def log_path():
    with tempfile.TemporaryDirectory() as d:
        yield os.path.join(d, "receipts.log")


def test_returns_nothing_when_the_log_file_does_not_exist_yet(log_path):
    log = ReceiptLog(log_path)
    assert log.load_unacked() == []


def test_returns_a_pending_entry_that_was_never_acked(log_path):
    log = ReceiptLog(log_path)
    log.append_pending(QueuedReceipt(receipt_id="rcpt_1", payload={"status": "DENY"}))

    assert log.load_unacked() == [QueuedReceipt(receipt_id="rcpt_1", payload={"status": "DENY"})]


def test_excludes_an_entry_once_it_has_been_acked(log_path):
    log = ReceiptLog(log_path)
    log.append_pending(QueuedReceipt(receipt_id="rcpt_1", payload={"status": "DENY"}))
    log.append_ack("rcpt_1")

    assert log.load_unacked() == []


def test_simulates_a_crash_between_the_decision_and_the_flush(log_path):
    writer = ReceiptLog(log_path)
    writer.append_pending(QueuedReceipt(receipt_id="rcpt_crash", payload={"status": "ALLOW"}))
    # No append_ack call -- simulates the process dying before the flush completed.

    reader = ReceiptLog(log_path)
    assert reader.load_unacked() == [QueuedReceipt(receipt_id="rcpt_crash", payload={"status": "ALLOW"})]


def test_compact_drops_acked_history_but_keeps_unacked_entries(log_path):
    log = ReceiptLog(log_path)
    log.append_pending(QueuedReceipt(receipt_id="rcpt_done", payload={"status": "ALLOW"}))
    log.append_ack("rcpt_done")
    log.append_pending(QueuedReceipt(receipt_id="rcpt_pending", payload={"status": "DENY"}))

    log.compact()

    assert log.load_unacked() == [QueuedReceipt(receipt_id="rcpt_pending", payload={"status": "DENY"})]


def test_compact_on_an_all_acked_log_leaves_an_empty_but_existing_file(log_path):
    log = ReceiptLog(log_path)
    log.append_pending(QueuedReceipt(receipt_id="rcpt_1", payload={}))
    log.append_ack("rcpt_1")

    log.compact()

    assert os.path.exists(log_path)
    assert log.load_unacked() == []
