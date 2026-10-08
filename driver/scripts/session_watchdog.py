#!/usr/bin/env python3
"""Bounded same-thread CLI recovery; never overlaps its recorded live owner.

Invoked by a transient user systemd timer. Configuration and output are private
task state, not credentials. Goal state is read through the public app-server
protocol; this script never changes it or starts a different thread.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import stat
import subprocess
import time


def birth_ticks(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def owner_alive(config):
    return birth_ticks(config["owner_pid"]) == config["owner_birth_ticks"]


def other_resume_running(thread_id):
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            args = (proc / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        if b"resume" in args and thread_id.encode() in args:
            return True
    return False


def user_fingerprint(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def continuation_context(payload):
    # The recorded CLI attaches these kinds itself. Do not infer control input
    # from text prefixes: a user's "stop" inside matching XML is still input.
    # Unknown or missing metadata remains a new user message (fail closed).
    kinds = payload.get("internal_chat_message_metadata_passthrough", {}).get("content_item_kinds", [])
    return bool(kinds) and all(kind in {"goal.internal_context", "environments.environment_context"} for kind in kinds)


def new_user_input(config):
    """Any new real user message invalidates this unattended authorization."""
    latest = None
    with open(config["rollout"], encoding="utf-8") as rollout:
        for line in rollout:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                # An appending runner may not have finished its final line.
                continue
            payload = item.get("payload", {})
            if item.get("type") != "response_item" or payload.get("role") != "user":
                continue
            if continuation_context(payload):
                continue
            content = payload.get("content", [])
            texts = [part.get("text", "") for part in content if part.get("type") == "input_text"]
            if texts == [config["resume_prompt"]]:
                continue
            latest = payload
    return latest is None or user_fingerprint(latest) != config["authorizing_user_fingerprint"]


def goal_status(config):
    server = subprocess.Popen(
        [config["codex"], "app-server"], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    pending = bytearray()

    def send(item):
        server.stdin.write((json.dumps(item) + "\n").encode())
        server.stdin.flush()

    def receive(request_id):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            while b"\n" in pending:
                line, _, remainder = pending.partition(b"\n")
                pending[:] = remainder
                item = json.loads(line)
                if item.get("id") == request_id:
                    if "error" in item:
                        raise RuntimeError("public goal API rejected request")
                    return item["result"]
            ready = select.select([server.stdout], [], [], max(0, deadline - time.monotonic()))[0]
            if not ready:
                break
            data = os.read(server.stdout.fileno(), 65536)
            if not data:
                raise RuntimeError("public goal API closed")
            pending.extend(data)
        raise TimeoutError("public goal API timeout")

    try:
        send({"id": 1, "method": "initialize", "params": {
            "clientInfo": {"name": "safeupload_watchdog", "version": "1"},
            "capabilities": {"experimentalApi": True}}})
        receive(1)
        send({"method": "initialized"})
        send({"id": 2, "method": "thread/goal/get", "params": {"threadId": config["thread_id"]}})
        goal = receive(2)["goal"]
        return goal["status"] if goal else "absent"
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


def admission(config, now, status, owner, other, changed_user):
    if now >= config["expires_at"]:
        return "expired"
    if changed_user:
        return "new-user-input"
    if status != "active":
        return "goal-" + status
    if owner:
        return "owner-alive"
    if other:
        return "resume-already-running"
    return "resume"


def log(state, event, **fields):
    record = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "event": event, **fields}
    with open(state / "watchdog.jsonl", "a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")
    print(json.dumps(record), flush=True)


def self_test():
    c = {"expires_at": 100}
    assert admission(c, 50, "active", False, False, False) == "resume"
    assert admission(c, 100, "active", False, False, False) == "expired"
    assert admission(c, 50, "active", True, False, False) == "owner-alive"
    assert admission(c, 50, "active", False, True, False) == "resume-already-running"
    assert admission(c, 50, "active", False, False, True) == "new-user-input"
    for status in ("absent", "paused", "blocked", "usageLimited", "budgetLimited", "complete"):
        assert admission(c, 50, status, False, False, False) == "goal-" + status
    assert birth_ticks(os.getpid()) is not None
    assert birth_ticks(999999999) is None
    def context(kind):
        return {"content": [{"type": "input_text", "text": '<codex_internal_context source="goal">stop</codex_internal_context>'}],
                "internal_chat_message_metadata_passthrough": {"content_item_kinds": kind}}
    assert continuation_context(context(["goal.internal_context"]))
    assert continuation_context(context(["environments.environment_context"]))
    assert not continuation_context(context(["user.text"]))
    assert not continuation_context(context(["unknown.kind"]))
    assert not continuation_context(context(["goal.internal_context", "user.text"]))
    assert not continuation_context({"content": context(["user.text"])["content"]})
    print("PASS: active-only, expiry, pause/limits/completion, new input, owner/overlap, recorded control context and text-spoof guards")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.config:
        parser.error("--config required")
    os.umask(0o077)
    info = args.config.stat()
    state = args.config.parent
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise RuntimeError("config must be owned by this user with mode 0600")
    if stat.S_IMODE(state.stat().st_mode) != 0o700:
        raise RuntimeError("state directory must have mode 0700")
    with open(state / "watchdog.lock", "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        config = json.loads(args.config.read_text())
        try:
            status = goal_status(config)
            decision = admission(config, time.time(), status, owner_alive(config),
                                 other_resume_running(config["thread_id"]), new_user_input(config))
            branch = subprocess.check_output(["git", "branch", "--show-current"],
                                             cwd=config["repo"], text=True).strip()
            if branch != config["branch"]:
                decision = "branch-changed"
            log(state, "probe", decision=decision, goal_status=status, dry_run=args.dry_run)
            if decision != "resume" or args.dry_run:
                return
            # The existing session has full access and no interactive approvals.
            # Preserve those permissions and the original CLI version/config;
            # no model override, new thread, or --dangerously-bypass flag.
            command = [config["codex"], "--approve-for-me", "exec", "resume",
                       "-c", 'approval_policy="never"', "-c", 'sandbox_mode="danger-full-access"',
                       "--json", config["thread_id"], "-"]
            output = state / f"resume-{int(time.time())}.jsonl"
            with open(output, "wb") as stream:
                runner = subprocess.Popen(command, cwd=config["repo"], stdin=subprocess.PIPE,
                                          stdout=stream, stderr=subprocess.STDOUT)
                log(state, "resume-started", pid=runner.pid, birth_ticks=birth_ticks(runner.pid),
                    thread_id=config["thread_id"], output=str(output))
                runner.communicate(config["resume_prompt"].encode())
                log(state, "resume-exited", pid=runner.pid, exit_code=runner.returncode)
            # Keep the lock until the runner exits; expiry prevents new starts,
            # rather than interrupting a driver experiment already in progress.
        except Exception as error:
            log(state, "probe-error", error=type(error).__name__)
            raise


if __name__ == "__main__":
    main()
