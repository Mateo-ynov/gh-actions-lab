"""
VulnTasker — Functional Test Suite
====================================
All tests below PASS — yet the app has 6 security vulnerabilities.

💡 Key insight for Exercise 1:
   Green tests ≠ Secure code.
   Functional tests verify behaviour; security tools find vulnerabilities.
"""

import pytest
import app as app_module
from app import app


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_database():
    """Reset the in-memory database before every test."""
    app_module._db = None
    yield
    app_module._db = None


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ── Health ────────────────────────────────────────────────────────────────────

def test_health_returns_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


# ── Tasks ─────────────────────────────────────────────────────────────────────

def test_list_all_tasks(client):
    resp = client.get("/tasks")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "tasks" in data
    assert len(data["tasks"]) == 4  # matches seed data


def test_filter_tasks_by_owner(client):
    resp = client.get("/tasks?owner=alice")
    assert resp.status_code == 200
    tasks = resp.get_json()["tasks"]
    assert len(tasks) == 2
    assert all(t["owner"] == "alice" for t in tasks)


def test_filter_unknown_owner_returns_empty(client):
    resp = client.get("/tasks?owner=nobody")
    assert resp.status_code == 200
    assert resp.get_json()["tasks"] == []


def test_create_task(client):
    payload = {"title": "Deploy new version", "owner": "dave"}
    resp = client.post("/tasks", json=payload)
    assert resp.status_code == 201
    # Verify it was persisted
    tasks = client.get("/tasks?owner=dave").get_json()["tasks"]
    assert len(tasks) == 1
    assert tasks[0]["title"] == "Deploy new version"


# ── Auth ──────────────────────────────────────────────────────────────────────

def test_login_valid_credentials_returns_token(client):
    resp = client.post("/login", json={"username": "admin", "password": "admin123"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "token" in data
    assert len(data["token"]) > 0


def test_login_wrong_password_returns_401(client):
    resp = client.post("/login", json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_login_unknown_user_returns_401(client):
    resp = client.post("/login", json={"username": "hacker", "password": "x"})
    assert resp.status_code == 401


# ── Export ────────────────────────────────────────────────────────────────────

def test_export_without_token_returns_403(client):
    resp = client.get("/export")
    assert resp.status_code == 403


def test_export_with_valid_token(client):
    # Get a valid token first
    token = client.post(
        "/login", json={"username": "admin", "password": "admin123"}
    ).get_json()["token"]

    resp = client.get("/export", headers={"X-Token": token})
    assert resp.status_code == 200
    assert "exported_to" in resp.get_json()


# ─────────────────────────────────────────────────────────────────────────────
# 🔴 All 10 tests pass. Coverage > 85%.
#    But none of them caught:
#      - SQL injection in /tasks
#      - Password logged in plaintext
#      - MD5 used instead of bcrypt
#      - Command injection in /export
#      - Hardcoded ADMIN_TOKEN in source code
#      - debug=True in production
#
#    That's exactly why we need security tools on top of tests.
# ─────────────────────────────────────────────────────────────────────────────
