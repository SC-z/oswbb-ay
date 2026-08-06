#!/usr/bin/env python3
"""Self-contained OSWbb evidence extractor. Python standard library only."""

from __future__ import annotations

import argparse
import gzip
import json
import math
import os
import re
import statistics
import sys
import tarfile
import tempfile
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator


CST = timezone(timedelta(hours=8), "CST")
SNAPSHOT = "2026-07-24"
MODULES = ("iostat", "meminfo", "top", "mpstat")
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}

IO = {
    "queue_hard": 1.0,
    "queue_soft": 0.3,
    "cpu_wait_hard": 20.0,
    "cpu_wait_soft": 10.0,
    "latency_iops_soft": 10.0,
    "util_hard": 95.0,
    "util_soft": 80.0,
    "util_min_samples": 3,
    "nvme_latency_hard": 8.0,
    "nvme_latency_soft": 6.0,
    "default_latency_hard": 50.0,
    "default_latency_soft": 37.5,
    "zscore": 3.0,
    "mad": 3.0,
    "iqr_multiplier": 1.5,
}
MEM = {
    "available_warn": 20.0,
    "available_soft": 30.0,
    "available_severe": 10.0,
    "anon_hard_mb": 200.0,
    "anon_soft_mb": 128.0,
    "anon_hard_rate_per_sample": 50.0,
    "anon_soft_rate_per_sample": 20.0,
    "anon_sample_seconds": 5.0,
    "anon_hard_pct": 5.0,
    "anon_soft_pct": 1.0,
    "swap_warn_pct": 10.0,
    "swap_growth_soft_mb": 128.0,
    "commit_warn_pct": 90.0,
    "commit_hard_pct": 100.0,
    "slab_warn_mb": 20480.0,
    "slab_soft_mb": 10240.0,
    "slab_warn_pct": 8.0,
    "slab_soft_pct": 4.0,
    "unreclaim_warn_pct": 2.0,
    "unreclaim_soft_pct": 1.0,
    "dirty_soft_pct": 2.0,
    "dirty_hard_pct": 5.0,
    "writeback_soft_pct": 0.2,
    "writeback_hard_pct": 1.0,
    "writeback_soft_mb": 256.0,
    "writeback_hard_mb": 1024.0,
    "anon_window_points": 36,
}
TOP = {
    "idle_hard": 10.0,
    "idle_soft": 20.0,
    "wait_hard": 20.0,
    "wait_soft": 10.0,
    "steal_hard": 10.0,
    "steal_soft": 5.0,
    "load_soft": 4.0,
    "load_hard": 8.0,
    "load_per_cpu_soft": 0.70,
    "load_per_cpu_hard": 1.00,
    "runnable_per_cpu": 0.70,
    "runnable_soft": 8,
    "idle_high": 80.0,
    "process_cpu": 50.0,
    "process_mem": 5.0,
}

STAMP_RE = re.compile(
    r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
    r"([A-Z][a-z]{2})\s+(\d{1,2})\s+"
    r"(\d{2}:\d{2}:\d{2})\s+\S+\s+(\d{4})"
)
CPU_COUNT_RE = re.compile(r"\(([0-9]+)\s+CPU\)")
HOST_RE = re.compile(r"^(.*?)_(?:iostat|meminfo|top|mpstat)_", re.I)
MODULE_RE = {
    module: re.compile(rf"(?:^|[/_])(?:osw)?{module}(?:[/_.]|$)", re.I)
    for module in MODULES
}


def iso(value: datetime | None) -> str:
    return value.isoformat(timespec="seconds") if value else ""


def parse_timestamp(line: str) -> datetime | None:
    match = STAMP_RE.search(line)
    if not match:
        return None
    try:
        return datetime.strptime(
            f"{match.group(1)} {match.group(2)} {match.group(3)} {match.group(4)}",
            "%b %d %H:%M:%S %Y",
        ).replace(tzinfo=CST)
    except ValueError:
        return None


def parse_window(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=CST)
    except ValueError as exc:
        raise SystemExit(f"invalid time {value!r}; expected YYYY-MM-DD HH:MM:SS") from exc


def in_window(at: datetime, start: datetime | None, end: datetime | None) -> bool:
    return (start is None or at >= start) and (end is None or at <= end)


def open_text(path: Path):
    if path.name.lower().endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def module_for(path: Path) -> str | None:
    text = str(path).lower()
    for module, pattern in MODULE_RE.items():
        if pattern.search(text):
            return module
    return None


def host_for(path: Path) -> str:
    name = path.name[:-3] if path.name.lower().endswith(".gz") else path.name
    match = HOST_RE.match(name)
    return match.group(1) if match and match.group(1) else "unknown"


def is_log_file(path: Path) -> bool:
    lowered = path.name.lower()
    return (
        path.is_file()
        and not path.name.startswith("._")
        and "__MACOSX" not in path.parts
        and (
        lowered.endswith(".dat")
        or lowered.endswith(".dat.gz")
        or any(token in lowered for token in ("iostat", "meminfo", "top", "mpstat"))
        )
    )


def discover(root: Path) -> dict[str, dict[str, list[Path]]]:
    grouped: dict[str, dict[str, list[Path]]] = defaultdict(lambda: defaultdict(list))
    candidates = [root] if root.is_file() else root.rglob("*")
    for path in candidates:
        if not is_log_file(path):
            continue
        module = module_for(path)
        if module:
            grouped[host_for(path)][module].append(path)
    for modules in grouped.values():
        for paths in modules.values():
            paths.sort()
    return grouped


def is_tar_path(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz"))


@contextmanager
def prepared_input(path: Path) -> Iterator[Path]:
    if not is_tar_path(path):
        yield path
        return
    with tempfile.TemporaryDirectory(prefix="oswbb-ops-") as tmp:
        destination = Path(tmp)
        with tarfile.open(path, "r:*") as archive:
            for member in archive.getmembers():
                member_path = Path(member.name)
                if (
                    member_path.is_absolute()
                    or ".." in member_path.parts
                    or member.issym()
                    or member.islnk()
                    or not (member.isfile() or member.isdir())
                ):
                    raise ValueError(f"unsafe archive member: {member.name}")
            try:
                archive.extractall(destination, filter="data")
            except TypeError:
                archive.extractall(destination)
        yield destination


def scan_times(paths: Iterable[Path], start: datetime | None, end: datetime | None):
    times: list[datetime] = []
    errors: list[str] = []
    for path in paths:
        try:
            with open_text(path) as handle:
                for line in handle:
                    if not line.startswith("zzz ***"):
                        continue
                    at = parse_timestamp(line)
                    if at and in_window(at, start, end):
                        times.append(at)
        except (OSError, EOFError) as exc:
            errors.append(f"{path}: {exc}")
    times.sort()
    return times, errors


def coverage(paths: list[Path], start: datetime | None, end: datetime | None):
    times, errors = scan_times(paths, start, end)
    deltas = [
        (right - left).total_seconds()
        for left, right in zip(times, times[1:])
        if right > left
    ]
    interval = statistics.median(deltas) if deltas else 0
    gap_limit = interval * 2.5 if interval else 0
    gaps = [
        {"start": iso(left), "end": iso(right), "seconds": delta}
        for left, right, delta in (
            (left, right, (right - left).total_seconds())
            for left, right in zip(times, times[1:])
        )
        if gap_limit and delta > gap_limit
    ]
    return {
        "files": len(paths),
        "samples": len(times),
        "start": iso(times[0]) if times else "",
        "end": iso(times[-1]) if times else "",
        "median_interval_seconds": interval,
        "gaps": gaps[:50],
        "gaps_truncated": len(gaps) > 50,
        "errors": errors,
    }


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = pct / 100.0 * (len(ordered) - 1)
    lower, upper = math.floor(index), math.ceil(index)
    if lower == upper:
        return ordered[lower]
    weight = index - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def metric_stats(values: list[float]) -> dict[str, float]:
    if not values:
        return {"count": 0, "mean": 0, "stddev": 0, "p50": 0, "p95": 0, "p99": 0, "mad": 0}
    mean = sum(values) / len(values)
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    p50 = percentile(values, 50)
    return {
        "count": len(values),
        "mean": mean,
        "stddev": math.sqrt(variance),
        "p50": p50,
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
        "mad": percentile([abs(value - p50) for value in values], 50),
    }


def finding(
    rule: str,
    module: str,
    classification: str,
    severity: str,
    title: str,
    at: datetime,
    metric: str,
    operator: str,
    threshold: float,
    observed: float,
    evidence: str,
    metrics: dict[str, Any] | None = None,
):
    return {
        "rule_id": rule,
        "module": module,
        "classification": classification,
        "severity": severity,
        "title": title,
        "time": iso(at),
        "metric": metric,
        "operator": operator,
        "threshold": threshold,
        "observed": observed,
        "evidence": evidence,
        "metrics": metrics or {},
    }


def normalize_header(value: str) -> str:
    return value.strip().lower().rstrip(":").replace("_", "-")


def value_from(fields: list[str], header: dict[str, int], *names: str) -> float:
    for name in names:
        index = header.get(normalize_header(name))
        if index is None or index >= len(fields):
            continue
        try:
            return float(fields[index])
        except ValueError:
            pass
    return 0.0


def parse_iostat(paths: list[Path], start: datetime | None, end: datetime | None):
    snapshots: list[dict[str, Any]] = []
    errors: list[str] = []
    for path in paths:
        current = None
        header: dict[str, int] = {}
        expect_cpu = False
        try:
            with open_text(path) as handle:
                for raw in handle:
                    line = raw.strip()
                    if line.startswith("zzz ***"):
                        if current:
                            snapshots.append(current)
                        at = parse_timestamp(line)
                        current = {"time": at, "cpu": {}, "devices": []} if at and in_window(at, start, end) else None
                        expect_cpu = False
                        continue
                    if current is None:
                        continue
                    if expect_cpu:
                        expect_cpu = False
                        fields = line.split()
                        if len(fields) >= 6:
                            try:
                                values = [float(value) for value in fields[:6]]
                                current["cpu"] = dict(zip(("user", "nice", "system", "iowait", "steal", "idle"), values))
                            except ValueError:
                                pass
                        continue
                    if "%user" in line:
                        expect_cpu = True
                        continue
                    if line.startswith("Device"):
                        columns = line.split()[1:]
                        header = {normalize_header(column): index + 1 for index, column in enumerate(columns)}
                        continue
                    if not line or not header:
                        continue
                    fields = line.split()
                    if len(fields) < 2 or fields[0] in {"Linux", "avg-cpu:"}:
                        continue
                    device = {
                        "name": fields[0],
                        "read_iops": value_from(fields, header, "r/s"),
                        "write_iops": value_from(fields, header, "w/s"),
                        "discard_iops": value_from(fields, header, "d/s"),
                        "read_kbps": value_from(fields, header, "rkb/s"),
                        "write_kbps": value_from(fields, header, "wkb/s"),
                        "discard_kbps": value_from(fields, header, "dkb/s"),
                        "read_await": value_from(fields, header, "r-await", "await"),
                        "write_await": value_from(fields, header, "w-await", "await"),
                        "discard_await": value_from(fields, header, "d-await"),
                        "queue": value_from(fields, header, "aqu-sz", "avgqu-sz"),
                        "util": value_from(fields, header, "%util"),
                    }
                    current["devices"].append(device)
            if current:
                snapshots.append(current)
        except (OSError, EOFError) as exc:
            errors.append(f"{path}: {exc}")
    snapshots.sort(key=lambda item: item["time"])
    return snapshots, errors


def active(device: dict[str, float]) -> bool:
    return (
        device["read_iops"] > 0
        or device["write_iops"] > 0
        or device["discard_iops"] > 0
        or device["read_kbps"] > 0
        or device["write_kbps"] > 0
        or device["discard_kbps"] > 0
    )


def iops(device: dict[str, float]) -> float:
    return device["read_iops"] + device["write_iops"] + device["discard_iops"]


def latency_thresholds(device: str):
    if device.startswith("nvme"):
        return IO["nvme_latency_soft"], IO["nvme_latency_hard"]
    return IO["default_latency_soft"], IO["default_latency_hard"]


def analyze_iostat(snapshots: list[dict[str, Any]]):
    results = []
    if not snapshots:
        return results
    waits = [(snap["time"], snap["cpu"].get("iowait", 0.0), snap) for snap in snapshots]
    peak_time, peak_wait, peak_snap = max(waits, key=lambda item: item[1])
    soft_count = sum(value >= IO["cpu_wait_soft"] for _, value, _ in waits)
    hard_count = sum(value >= IO["cpu_wait_hard"] for _, value, _ in waits)
    average = sum(value for _, value, _ in waits) / len(waits)
    wait_corroborated = any(
        active(device)
        and (
            device["queue"] >= IO["queue_soft"]
            or (device["read_iops"] > 0 and device["read_await"] >= latency_thresholds(device["name"])[0])
            or (device["write_iops"] > 0 and device["write_await"] >= latency_thresholds(device["name"])[0])
            or (device["discard_iops"] > 0 and device["discard_await"] >= latency_thresholds(device["name"])[0])
        )
        for device in peak_snap["devices"]
    )
    severity = ""
    if hard_count >= 2 or (len(waits) >= 2 and average >= IO["cpu_wait_hard"]) or (peak_wait >= IO["cpu_wait_hard"] and wait_corroborated):
        severity = "high"
    elif soft_count >= 2 or (len(waits) >= 2 and average >= IO["cpu_wait_soft"]) or (peak_wait >= IO["cpu_wait_soft"] and wait_corroborated):
        severity = "medium"
    if severity:
        results.append(finding(
            "iostat-cpu-iowait", "iostat", "risk" if wait_corroborated or soft_count >= 2 else "candidate",
            severity, "iostat 采样中 CPU iowait 偏高", peak_time, "cpu_iowait_max_pct", ">=",
            IO["cpu_wait_hard"] if severity == "high" else IO["cpu_wait_soft"], peak_wait,
            f"iowait 平均 {average:.1f}%，峰值 {peak_wait:.1f}%；同采样磁盘佐证={wait_corroborated}",
            {"average": average, "soft_samples": soft_count, "hard_samples": hard_count, "corroborated": wait_corroborated},
        ))

    by_device: dict[str, list[tuple[datetime, dict[str, float], dict[str, Any]]]] = defaultdict(list)
    for snap in snapshots:
        for device in snap["devices"]:
            by_device[device["name"]].append((snap["time"], device, snap))

    latency_events: dict[tuple[str, datetime], set[str]] = defaultdict(set)
    for name, samples in sorted(by_device.items()):
        active_samples = [(at, device, snap) for at, device, snap in samples if active(device)]
        if not active_samples:
            continue
        soft_latency, hard_latency = latency_thresholds(name)
        for direction, await_key, activity_key in (
            ("read", "read_await", "read_iops"),
            ("write", "write_await", "write_iops"),
            ("discard", "discard_await", "discard_iops"),
        ):
            directional = [(at, device, snap) for at, device, snap in active_samples if device[activity_key] > 0]
            values = [device[await_key] for _, device, _ in directional]
            if not values:
                continue
            stats = metric_stats(values)
            hard = [(at, device, snap) for at, device, snap in directional if device[await_key] >= hard_latency]
            chosen = max(hard, key=lambda item: item[1][await_key]) if hard else None
            if not chosen and stats["p95"] >= soft_latency:
                supported = [
                    item for item in directional
                    if item[1][await_key] >= soft_latency
                    and (
                        iops(item[1]) >= IO["latency_iops_soft"]
                        or item[1]["queue"] >= IO["queue_soft"]
                        or item[2]["cpu"].get("iowait", 0.0) >= IO["cpu_wait_soft"]
                    )
                ]
                chosen = max(supported, key=lambda item: item[1][await_key]) if supported else None
            if not chosen:
                continue
            at, device, snap = chosen
            corroborated = (
                iops(device) >= IO["latency_iops_soft"]
                or device["queue"] >= IO["queue_soft"]
                or snap["cpu"].get("iowait", 0.0) >= IO["cpu_wait_soft"]
            )
            is_hard = device[await_key] >= hard_latency
            severity = "high" if is_hard and corroborated else "medium"
            results.append(finding(
                f"iostat-{direction}-latency-{name}", "iostat", "risk" if corroborated else "candidate",
                severity, f"{name} {direction} 延迟偏高", at, f"{direction}_await_ms", ">=",
                hard_latency if is_hard else soft_latency, device[await_key],
                f"P95={stats['p95']:.1f}ms，峰值={device[await_key]:.1f}ms，IOPS={iops(device):.2f}，队列={device['queue']:.2f}，iowait={snap['cpu'].get('iowait', 0.0):.1f}%",
                {"p95": stats["p95"], "p99": stats["p99"], "active_samples": len(values), "corroborated": corroborated},
            ))
            if is_hard and corroborated:
                latency_events[(direction, at)].add(name)

        queue_values = [(at, device, snap) for at, device, snap in active_samples]
        queue_avg = sum(item[1]["queue"] for item in queue_values) / len(queue_values)
        queue_peak = max(queue_values, key=lambda item: item[1]["queue"])
        hard_count = sum(item[1]["queue"] >= IO["queue_hard"] for item in queue_values)
        soft_count = sum(item[1]["queue"] >= IO["queue_soft"] for item in queue_values)
        at, device, snap = queue_peak
        queue_severity = ""
        if queue_avg >= IO["queue_hard"] and len(queue_values) >= 2:
            queue_severity = "high"
        elif device["queue"] >= IO["queue_hard"] and (
            snap["cpu"].get("iowait", 0.0) >= IO["cpu_wait_soft"] or iops(device) >= IO["latency_iops_soft"]
        ):
            queue_severity = "medium"
        elif queue_avg >= IO["queue_soft"] and len(queue_values) >= 2:
            queue_severity = "medium"
        if queue_severity:
            results.append(finding(
                f"iostat-queue-{name}", "iostat", "risk", queue_severity, f"{name} 队列深度偏高",
                at, "avg_queue_peak", ">=", IO["queue_hard"] if queue_severity == "high" else IO["queue_soft"],
                device["queue"], f"活跃样本平均队列={queue_avg:.2f}，峰值={device['queue']:.2f}，峰值 IOPS={iops(device):.2f}",
                {"active_samples": len(queue_values), "soft_samples": soft_count, "hard_samples": hard_count},
            ))

        util_values = [(at, device, snap) for at, device, snap in active_samples]
        if len(util_values) >= IO["util_min_samples"]:
            util_avg = sum(item[1]["util"] for item in util_values) / len(util_values)
            at, device, snap = max(util_values, key=lambda item: item[1]["util"])
            corroborated = any(
                item[1]["util"] >= IO["util_soft"]
                and (
                    item[1]["read_await"] >= soft_latency
                    or item[1]["write_await"] >= soft_latency
                    or item[1]["discard_await"] >= soft_latency
                    or item[1]["queue"] >= IO["queue_soft"]
                    or item[2]["cpu"].get("iowait", 0.0) >= IO["cpu_wait_soft"]
                )
                for item in util_values
            )
            hard_count = sum(item[1]["util"] >= IO["util_hard"] for item in util_values)
            soft_count = sum(item[1]["util"] >= IO["util_soft"] for item in util_values)
            util_severity = ""
            if corroborated and (hard_count >= IO["util_min_samples"] or util_avg >= IO["util_hard"]):
                util_severity = "high"
            elif corroborated and (soft_count >= IO["util_min_samples"] or util_avg >= IO["util_soft"]):
                util_severity = "medium"
            elif not corroborated and (hard_count >= IO["util_min_samples"] or util_avg >= IO["util_hard"]):
                util_severity = "medium"
            if util_severity:
                results.append(finding(
                    f"iostat-util-{name}", "iostat", "risk" if corroborated else "candidate",
                    util_severity, f"{name} 利用率持续偏高", at, "util_pct", ">=",
                    IO["util_hard"] if util_severity == "high" else IO["util_soft"], device["util"],
                    f"活跃样本平均 util={util_avg:.1f}%，峰值={device['util']:.1f}%，延迟/队列/iowait 佐证={corroborated}",
                    {"active_samples": len(util_values), "soft_samples": soft_count, "hard_samples": hard_count, "corroborated": corroborated},
                ))

    for (direction, at), devices in sorted(latency_events.items(), key=lambda item: item[0][1]):
        physical = sorted(device for device in devices if re.match(r"^(nvme|sd|vd|xvd|mpath)", device))
        if len(physical) >= 2:
            results.append(finding(
                f"iostat-multi-device-{direction}-{at.timestamp():.0f}", "iostat", "risk", "high",
                f"多块设备 {direction} 延迟同窗口偏高", at, f"{direction}_await_ms", ">=", 0, len(physical),
                "同采样受影响设备：" + ", ".join(physical), {"affected_devices": physical},
            ))
    return results


MEM_KEYS = {
    "MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "SwapTotal", "SwapFree",
    "AnonPages", "Dirty", "Writeback", "Slab", "SReclaimable", "SUnreclaim",
    "CommitLimit", "Committed_AS",
}


def parse_meminfo(paths: list[Path], start: datetime | None, end: datetime | None):
    snapshots = []
    errors = []
    for path in paths:
        current = None
        try:
            with open_text(path) as handle:
                for raw in handle:
                    line = raw.strip()
                    if line.startswith("zzz ***"):
                        if current:
                            snapshots.append(current)
                        at = parse_timestamp(line)
                        current = {"time": at, "values": {}, "present": set()} if at and in_window(at, start, end) else None
                        continue
                    if current is None or ":" not in line:
                        continue
                    fields = line.split()
                    key = fields[0].rstrip(":")
                    if key not in MEM_KEYS or len(fields) < 2:
                        continue
                    try:
                        current["values"][key] = int(fields[1])
                        current["present"].add(key)
                    except ValueError:
                        pass
            if current:
                snapshots.append(current)
        except (OSError, EOFError) as exc:
            errors.append(f"{path}: {exc}")
    snapshots.sort(key=lambda item: item["time"])
    return snapshots, errors


def ratio(num: float, den: float) -> float:
    return num / den * 100 if den else 0.0


def available_kb(values: dict[str, int]) -> int:
    if values.get("MemAvailable", 0) > 0:
        return values["MemAvailable"]
    result = sum(values.get(key, 0) for key in ("MemFree", "Buffers", "Cached", "SReclaimable"))
    return max(0, min(values.get("MemTotal", result), result))


def has_available(sample: dict[str, Any]) -> bool:
    values = sample["values"]
    return any(values.get(key, 0) > 0 for key in ("MemAvailable", "Buffers", "Cached", "SReclaimable"))


def current_trigger(samples: list[dict[str, Any]], trigger) -> bool:
    return bool(samples and trigger(samples[-1]))


def analyze_meminfo(snapshots: list[dict[str, Any]]):
    valid = [sample for sample in snapshots if sample["values"].get("MemTotal", 0) > 0]
    results = []
    if not valid:
        return results
    available_samples = [sample for sample in valid if has_available(sample)]
    if available_samples:
        scored = [(ratio(available_kb(sample["values"]), sample["values"]["MemTotal"]), sample) for sample in available_samples]
        worst_pct, worst = min(scored, key=lambda item: item[0])
        current_pct, current = scored[-1]
        soft_count = sum(value < MEM["available_soft"] for value, _ in scored)
        warn_count = sum(value < MEM["available_warn"] for value, _ in scored)
        if worst_pct < MEM["available_soft"]:
            severity = "high" if worst_pct < MEM["available_warn"] else "medium"
            recovered = current_pct >= MEM["available_soft"]
            if severity == "high" and warn_count <= 1 and recovered:
                severity = "medium"
            classification = "candidate" if recovered and soft_count <= 1 else "risk"
            results.append(finding(
                "meminfo-available", "meminfo", classification, severity, "可用内存偏低",
                worst["time"], "mem_available_pct", "<",
                MEM["available_warn"] if severity == "high" else MEM["available_soft"], worst_pct,
                f"窗口最低={worst_pct:.1f}% ({available_kb(worst['values'])/1024/1024:.2f}GB)，当前={current_pct:.1f}% ({available_kb(current['values'])/1024/1024:.2f}GB)",
                {"soft_samples": soft_count, "warn_samples": warn_count, "recovered": recovered},
            ))

    commit = [
        (ratio(sample["values"].get("Committed_AS", 0), sample["values"].get("CommitLimit", 0)), sample)
        for sample in valid if sample["values"].get("CommitLimit", 0) > 0 and sample["values"].get("Committed_AS", 0) > 0
    ]
    if commit:
        worst_pct, worst = max(commit, key=lambda item: item[0])
        current_pct = commit[-1][0]
        if worst_pct >= MEM["commit_warn_pct"]:
            severity = "high" if worst_pct >= MEM["commit_hard_pct"] else "medium"
            current_active = current_pct >= MEM["commit_warn_pct"]
            results.append(finding(
                "meminfo-commit", "meminfo", "risk" if current_active else "candidate", severity,
                "内存提交压力偏高", worst["time"], "committed_pct", ">=",
                MEM["commit_hard_pct"] if severity == "high" else MEM["commit_warn_pct"], worst_pct,
                f"Committed_AS 峰值占 CommitLimit {worst_pct:.1f}%，当前 {current_pct:.1f}%",
                {"current_pct": current_pct, "recovered": not current_active},
            ))

    swap = []
    min_used = None
    for sample in valid:
        values = sample["values"]
        if values.get("SwapTotal", 0) <= 0 or "SwapFree" not in sample["present"]:
            continue
        used = max(0, values["SwapTotal"] - values.get("SwapFree", 0))
        min_used = used if min_used is None else min(min_used, used)
        swap.append((ratio(used, values["SwapTotal"]), used, used - min_used, sample))
    if swap:
        worst_pct, used, growth, worst = max(swap, key=lambda item: item[0])
        current_pct, _, _, _ = swap[-1]
        if worst_pct >= MEM["swap_warn_pct"] or growth / 1024 >= MEM["swap_growth_soft_mb"]:
            current_active = current_pct >= MEM["swap_warn_pct"]
            results.append(finding(
                "meminfo-swap", "meminfo", "risk" if current_active else "candidate",
                "high" if worst_pct >= MEM["swap_warn_pct"] and current_active else "medium",
                "Swap 使用或增长偏高", worst["time"], "swap_used_pct", ">=", MEM["swap_warn_pct"], worst_pct,
                f"Swap 峰值={worst_pct:.1f}% ({used/1024:.1f}MB)，窗口增长={growth/1024:.1f}MB，当前={current_pct:.1f}%",
                {"growth_mb": growth / 1024, "current_pct": current_pct, "recovered": not current_active},
            ))

    slab_candidates = []
    for sample in valid:
        values = sample["values"]
        total = values["MemTotal"]
        slab_mb = values.get("Slab", 0) / 1024
        slab_pct = ratio(values.get("Slab", 0), total)
        unreclaim_pct = ratio(values.get("SUnreclaim", 0), total)
        trigger = None
        if unreclaim_pct >= MEM["unreclaim_warn_pct"]:
            trigger = ("high", "sunreclaim_pct", MEM["unreclaim_warn_pct"], unreclaim_pct)
        elif slab_mb >= MEM["slab_warn_mb"] and slab_pct >= MEM["slab_warn_pct"]:
            trigger = ("high", "slab_pct", MEM["slab_warn_pct"], slab_pct)
        elif unreclaim_pct >= MEM["unreclaim_soft_pct"]:
            trigger = ("medium", "sunreclaim_pct", MEM["unreclaim_soft_pct"], unreclaim_pct)
        elif slab_mb >= MEM["slab_soft_mb"] and slab_pct >= MEM["slab_soft_pct"]:
            trigger = ("medium", "slab_gb", MEM["slab_soft_mb"] / 1024, slab_mb / 1024)
        if trigger:
            slab_candidates.append((trigger, sample, slab_pct, unreclaim_pct))
    if slab_candidates:
        trigger, worst, slab_pct, unreclaim_pct = max(
            slab_candidates,
            key=lambda item: ((2 if item[0][0] == "high" else 1) * 1000 + item[0][3] / item[0][2]),
        )
        latest_has = bool(slab_candidates and slab_candidates[-1][1] is valid[-1])
        results.append(finding(
            "meminfo-slab", "meminfo", "risk" if latest_has else "candidate", trigger[0],
            "Slab/不可回收内存偏高", worst["time"], trigger[1], ">=", trigger[2], trigger[3],
            f"Slab={slab_pct:.2f}%，SUnreclaim={unreclaim_pct:.2f}%，当前仍触发={latest_has}",
            {"slab_pct": slab_pct, "sunreclaim_pct": unreclaim_pct, "recovered": not latest_has},
        ))

    writeback_candidates = []
    for sample in valid:
        values = sample["values"]
        total = values["MemTotal"]
        dirty_mb = values.get("Dirty", 0) / 1024
        writeback_mb = values.get("Writeback", 0) / 1024
        dirty_pct = ratio(values.get("Dirty", 0), total)
        writeback_pct = ratio(values.get("Writeback", 0), total)
        has_dirty = dirty_pct >= MEM["dirty_soft_pct"] or (
            dirty_mb >= MEM["writeback_soft_mb"] and writeback_pct >= MEM["writeback_soft_pct"]
        )
        trigger = None
        if has_dirty and writeback_mb > 0:
            if writeback_pct >= MEM["writeback_hard_pct"] or (
                writeback_mb >= MEM["writeback_hard_mb"] and writeback_pct >= MEM["writeback_soft_pct"]
            ):
                trigger = ("high", "writeback_pct", MEM["writeback_hard_pct"], writeback_pct)
            elif dirty_pct >= MEM["dirty_hard_pct"] and writeback_pct >= MEM["writeback_soft_pct"]:
                trigger = ("high", "dirty_pct", MEM["dirty_hard_pct"], dirty_pct)
            elif writeback_pct >= MEM["writeback_soft_pct"] or (
                writeback_mb >= MEM["writeback_soft_mb"] and dirty_pct >= MEM["dirty_soft_pct"]
            ):
                trigger = ("medium", "writeback_pct", MEM["writeback_soft_pct"], writeback_pct)
        if trigger:
            writeback_candidates.append((trigger, sample, dirty_mb, writeback_mb, dirty_pct, writeback_pct))
    if writeback_candidates:
        trigger, worst, dirty_mb, writeback_mb, dirty_pct, writeback_pct = max(
            writeback_candidates,
            key=lambda item: ((2 if item[0][0] == "high" else 1) * 1000 + item[0][3] / item[0][2]),
        )
        latest_has = writeback_candidates[-1][1] is valid[-1]
        results.append(finding(
            "meminfo-writeback-pressure", "meminfo", "risk" if latest_has else "candidate", trigger[0],
            "Dirty/Writeback 回写积压", worst["time"], trigger[1], ">=", trigger[2], trigger[3],
            f"Dirty={dirty_mb:.1f}MB ({dirty_pct:.2f}%)，Writeback={writeback_mb:.1f}MB ({writeback_pct:.2f}%)",
            {"dirty_pct": dirty_pct, "writeback_pct": writeback_pct, "recovered": not latest_has},
        ))

    best_anon = None
    for end_index in range(1, len(valid)):
        start_limit = max(0, end_index - MEM["anon_window_points"] + 1)
        start_index = min(range(start_limit, end_index), key=lambda index: valid[index]["values"].get("AnonPages", 0))
        start_sample, end_sample = valid[start_index], valid[end_index]
        delta_mb = (end_sample["values"].get("AnonPages", 0) - start_sample["values"].get("AnonPages", 0)) / 1024
        if delta_mb <= 0:
            continue
        elapsed_minutes = max((end_sample["time"] - start_sample["time"]).total_seconds() / 60, MEM["anon_sample_seconds"] / 60)
        rate = delta_mb / elapsed_minutes
        sustained = end_index - start_index >= 2
        end_values = end_sample["values"]
        pressure = (
            (has_available(end_sample) and ratio(available_kb(end_values), end_values["MemTotal"]) < MEM["available_soft"])
            or (end_values.get("CommitLimit", 0) > 0 and ratio(end_values.get("Committed_AS", 0), end_values["CommitLimit"]) >= MEM["commit_warn_pct"])
        )
        if not sustained and not pressure:
            continue
        candidate = (delta_mb, rate, start_sample, end_sample, pressure)
        if best_anon is None or candidate[:2] > best_anon[:2]:
            best_anon = candidate
    if best_anon:
        delta_mb, rate, start_sample, end_sample, pressure = best_anon
        hard_rate = MEM["anon_hard_rate_per_sample"] * 60 / MEM["anon_sample_seconds"]
        soft_rate = MEM["anon_soft_rate_per_sample"] * 60 / MEM["anon_sample_seconds"]
        severity = ""
        if delta_mb >= MEM["anon_hard_mb"] and rate >= hard_rate:
            severity = "high"
        elif delta_mb >= MEM["anon_soft_mb"] and rate >= soft_rate:
            severity = "medium"
        if severity:
            delta_pct = ratio(delta_mb * 1024, end_sample["values"]["MemTotal"])
            if not pressure and delta_pct < MEM["anon_soft_pct"]:
                severity = "low"
            elif not pressure and delta_pct < MEM["anon_hard_pct"]:
                severity = "medium"
            results.append(finding(
                "meminfo-anon-growth", "meminfo", "risk" if pressure else "candidate", severity,
                "匿名页持续增长", end_sample["time"], "anon_growth_mb", ">=",
                MEM["anon_hard_mb"] if severity == "high" else MEM["anon_soft_mb"], delta_mb,
                f"AnonPages 增长={delta_mb:.1f}MB，速率={rate:.1f}MB/min，相对内存={delta_pct:.2f}%，压力佐证={pressure}",
                {"start": iso(start_sample["time"]), "rate_mb_per_minute": rate, "delta_pct": delta_pct, "pressure": pressure},
            ))
    return results


def parse_top_memory(value: str) -> int | None:
    if not value:
        return None
    multipliers = {"g": 1024 * 1024, "m": 1024, "k": 1}
    suffix = value[-1].lower()
    multiplier = multipliers.get(suffix, 1)
    number = value[:-1] if suffix in multipliers else value
    try:
        return int(float(number) * multiplier)
    except ValueError:
        return None


def parse_top(paths: list[Path], start: datetime | None, end: datetime | None):
    snapshots = []
    errors = []
    for path in paths:
        current = None
        has_cpu = False
        in_processes = False
        try:
            with open_text(path) as handle:
                for raw in handle:
                    line = raw.strip()
                    if line.startswith("zzz ***"):
                        if current and has_cpu:
                            snapshots.append(current)
                        at = parse_timestamp(line)
                        current = {"time": at, "processes": []} if at and in_window(at, start, end) else None
                        has_cpu = False
                        in_processes = False
                        continue
                    if current is None:
                        continue
                    if "load average:" in line:
                        fields = [part.strip() for part in line.split("load average:", 1)[1].split(",")]
                        try:
                            current["load1"], current["load5"], current["load15"] = map(float, fields[:3])
                        except (ValueError, IndexError):
                            pass
                        in_processes = False
                    elif line.startswith("Tasks:"):
                        numbers = re.search(r"(\d+)\s+total.*?(\d+)\s+running.*?(\d+)\s+sleeping.*?(\d+)\s+stopped.*?(\d+)\s+zombie", line)
                        if numbers:
                            values = [int(value) for value in numbers.groups()]
                            for key, value in zip(("total", "running", "sleeping", "stopped", "zombie"), values):
                                current[key] = value
                        in_processes = False
                    elif line.startswith(("%Cpu(s):", "Cpu(s):")):
                        for value, key in re.findall(r"([0-9.]+)\s*([a-z]{2})", line.split(":", 1)[1]):
                            current[{"us": "cpu_user", "sy": "cpu_sys", "ni": "cpu_nice", "id": "cpu_idle", "wa": "cpu_wait", "hi": "cpu_hi", "si": "cpu_si", "st": "cpu_steal"}.get(key, key)] = float(value)
                            has_cpu = True
                        in_processes = False
                    elif line.split()[:2] == ["PID", "USER"]:
                        in_processes = True
                    elif in_processes:
                        fields = line.split()
                        if len(fields) < 12:
                            continue
                        try:
                            process = {
                                "pid": int(fields[0]), "user": fields[1], "state": fields[7],
                                "cpu": float(fields[8]), "mem": float(fields[9]),
                                "virt_kb": parse_top_memory(fields[4]), "res_kb": parse_top_memory(fields[5]),
                                "command": " ".join(fields[11:]),
                            }
                        except ValueError:
                            continue
                        current["processes"].append(process)
            if current and has_cpu:
                snapshots.append(current)
        except (OSError, EOFError) as exc:
            errors.append(f"{path}: {exc}")
    snapshots.sort(key=lambda item: item["time"])
    return snapshots, errors


def parse_cpu_count(paths: list[Path]) -> tuple[int, list[str]]:
    errors = []
    for path in paths:
        try:
            with open_text(path) as handle:
                for line in handle:
                    match = CPU_COUNT_RE.search(line)
                    if match and int(match.group(1)) > 0:
                        return int(match.group(1)), errors
        except (OSError, EOFError) as exc:
            errors.append(f"{path}: {exc}")
    return 0, errors


def analyze_top(snapshots: list[dict[str, Any]], cpu_count: int):
    results = []
    if not snapshots:
        return results
    for snap in snapshots:
        snap["cpu_count"] = cpu_count
    runnable_threshold = max(2, math.ceil(cpu_count * TOP["runnable_per_cpu"])) if cpu_count else TOP["runnable_soft"]
    load_soft = max(1.0, cpu_count * TOP["load_per_cpu_soft"]) if cpu_count else TOP["load_soft"]
    load_hard = cpu_count * TOP["load_per_cpu_hard"] if cpu_count else TOP["load_hard"]

    def summarize(key: str, maximum=True):
        average = sum(snap.get(key, 0.0) for snap in snapshots) / len(snapshots)
        chosen = (max if maximum else min)(snapshots, key=lambda snap: snap.get(key, 0.0))
        return average, chosen.get(key, 0.0), chosen

    idle_avg, idle_min, idle_snap = summarize("cpu_idle", maximum=False)
    idle_soft_count = sum(snap.get("cpu_idle", 0.0) <= TOP["idle_soft"] for snap in snapshots)
    idle_hard_count = sum(snap.get("cpu_idle", 0.0) <= TOP["idle_hard"] for snap in snapshots)
    high_process_at_idle = any(process["cpu"] >= TOP["process_cpu"] for process in idle_snap["processes"])
    runnable_at_idle = idle_snap.get("running", 0) >= runnable_threshold
    idle_corr = high_process_at_idle or runnable_at_idle
    idle_severity = ""
    if idle_hard_count >= 2 or (len(snapshots) >= 2 and idle_avg <= TOP["idle_hard"]) or (idle_min <= TOP["idle_hard"] and idle_corr):
        idle_severity = "high"
    elif idle_soft_count >= 2 or (len(snapshots) >= 2 and idle_avg <= TOP["idle_soft"]) or (idle_min <= TOP["idle_soft"] and idle_corr):
        idle_severity = "medium"
    if idle_severity:
        results.append(finding(
            "top-cpu-idle", "top", "risk" if idle_corr or idle_soft_count >= 2 else "candidate",
            idle_severity, "CPU 空闲率偏低", idle_snap["time"], "cpu_idle_min_pct", "<=",
            TOP["idle_hard"] if idle_severity == "high" else TOP["idle_soft"], idle_min,
            f"CPU Idle 平均={idle_avg:.1f}%，最低={idle_min:.1f}%，高 CPU 进程佐证={high_process_at_idle}，运行队列佐证={runnable_at_idle}",
            {"average": idle_avg, "soft_samples": idle_soft_count, "hard_samples": idle_hard_count},
        ))

    wait_avg, wait_max, wait_snap = summarize("cpu_wait")
    wait_soft_count = sum(snap.get("cpu_wait", 0.0) >= TOP["wait_soft"] for snap in snapshots)
    wait_hard_count = sum(snap.get("cpu_wait", 0.0) >= TOP["wait_hard"] for snap in snapshots)
    wait_corr = any(process["state"] == "D" for process in wait_snap["processes"]) or wait_snap.get("running", 0) >= runnable_threshold
    wait_severity = ""
    if wait_hard_count >= 2 or (len(snapshots) >= 2 and wait_avg >= TOP["wait_hard"]) or (wait_max >= TOP["wait_hard"] and wait_corr):
        wait_severity = "high"
    elif wait_soft_count >= 2 or (len(snapshots) >= 2 and wait_avg >= TOP["wait_soft"]) or (wait_max >= TOP["wait_soft"] and wait_corr):
        wait_severity = "medium"
    if wait_severity:
        results.append(finding(
            "top-cpu-wait", "top", "risk" if wait_corr else "candidate", wait_severity,
            "top 视角下 I/O wait 偏高", wait_snap["time"], "cpu_wait_max_pct", ">=",
            TOP["wait_hard"] if wait_severity == "high" else TOP["wait_soft"], wait_max,
            f"CPU Wait 平均={wait_avg:.1f}%，峰值={wait_max:.1f}%，同采样 D 状态/运行队列佐证={wait_corr}",
            {"average": wait_avg, "soft_samples": wait_soft_count, "hard_samples": wait_hard_count},
        ))

    steal_avg, steal_max, steal_snap = summarize("cpu_steal")
    steal_soft_count = sum(snap.get("cpu_steal", 0.0) >= TOP["steal_soft"] for snap in snapshots)
    steal_hard_count = sum(snap.get("cpu_steal", 0.0) >= TOP["steal_hard"] for snap in snapshots)
    if steal_max >= TOP["steal_soft"]:
        if steal_hard_count >= 2 or steal_avg >= TOP["steal_hard"]:
            severity, classification = "high", "risk"
        elif steal_soft_count >= 2 or steal_avg >= TOP["steal_soft"]:
            severity, classification = "medium", "risk"
        else:
            severity, classification = "low", "candidate"
        results.append(finding(
            "top-cpu-steal", "top", classification, severity, "CPU steal 偏高",
            steal_snap["time"], "cpu_steal_max_pct", ">=", TOP["steal_hard"] if severity == "high" else TOP["steal_soft"],
            steal_max, f"CPU Steal 平均={steal_avg:.1f}%，峰值={steal_max:.1f}%",
            {"average": steal_avg, "soft_samples": steal_soft_count, "hard_samples": steal_hard_count},
        ))

    zombie_snap = max(snapshots, key=lambda snap: snap.get("zombie", 0))
    zombie_max = zombie_snap.get("zombie", 0)
    zombie_samples = sum(snap.get("zombie", 0) > 0 for snap in snapshots)
    if zombie_max > 0:
        severity = "high" if zombie_max >= 2 else ("medium" if zombie_samples >= 2 else "low")
        results.append(finding(
            "top-zombie", "top", "risk" if severity != "low" else "candidate", severity,
            "存在僵尸进程", zombie_snap["time"], "task_zombie_max", ">", 0, zombie_max,
            f"僵尸进程并发峰值={zombie_max}，出现样本数={zombie_samples}",
            {"positive_samples": zombie_samples},
        ))

    d_snapshots = [snap for snap in snapshots if any(process["state"] == "D" for process in snap["processes"])]
    if d_snapshots:
        counts = Counter()
        representatives = {}
        max_concurrent = 0
        peak = d_snapshots[0]
        for snap in d_snapshots:
            current = {process["pid"]: process for process in snap["processes"] if process["state"] == "D"}
            if len(current) > max_concurrent:
                max_concurrent, peak = len(current), snap
            for pid, process in current.items():
                counts[pid] += 1
                representatives.setdefault(pid, process["command"])
        persistent = sum(count >= 2 for count in counts.values())
        pressure = any(
            snap.get("cpu_wait", 0.0) >= TOP["wait_soft"]
            or snap.get("cpu_idle", 100.0) <= TOP["idle_soft"]
            or snap.get("running", 0) >= runnable_threshold
            for snap in d_snapshots
        )
        severity = "high" if pressure and (max_concurrent >= 2 or persistent) else ("medium" if pressure or persistent else "low")
        examples = ", ".join(f"{pid}/{command}" for pid, command in list(representatives.items())[:5])
        results.append(finding(
            "top-process-d-state", "top", "risk" if pressure else "candidate", severity,
            "存在 D 状态进程", peak["time"], "d_state_process_count", ">", 0, max_concurrent,
            f"最大同采样并发={max_concurrent}，唯一 PID={len(counts)}，持续 PID={persistent}；{examples}",
            {"snapshot_count": len(d_snapshots), "persistent_processes": persistent, "pressure": pressure},
        ))

    high_cpu = []
    for snap in snapshots:
        if snap.get("cpu_idle", 100.0) > TOP["idle_soft"]:
            continue
        for process in snap["processes"]:
            if process["cpu"] >= TOP["process_cpu"]:
                high_cpu.append((process["cpu"], process, snap))
    if high_cpu:
        cpu, process, snap = max(high_cpu, key=lambda item: item[0])
        pids = Counter(item[1]["pid"] for item in high_cpu)
        persistent = sum(count >= 2 for count in pids.values())
        results.append(finding(
            "top-process-high-cpu", "top", "risk", "high" if len({item[2]["time"] for item in high_cpu}) >= 2 or persistent else "medium",
            "CPU 压力时存在高 CPU 进程", snap["time"], "process_cpu_pct", ">=", TOP["process_cpu"], cpu,
            f"PID={process['pid']} USER={process['user']} COMMAND={process['command']} CPU={cpu:.1f}%，系统 idle={snap.get('cpu_idle', 0):.1f}%",
            {"observations": len(high_cpu), "persistent_processes": persistent},
        ))

    high_load = [snap for snap in snapshots if snap.get("load1", 0.0) >= load_soft]
    if high_load:
        load_avg = sum(snap.get("load1", 0.0) for snap in snapshots) / len(snapshots)
        peak = max(high_load, key=lambda snap: snap.get("load1", 0.0))
        load_max = peak.get("load1", 0.0)
        low_idle = any(snap.get("cpu_idle", 100.0) < TOP["idle_soft"] for snap in high_load)
        runnable = any(snap.get("running", 0) >= runnable_threshold for snap in high_load)
        d_state = any(any(process["state"] == "D" for process in snap["processes"]) for snap in high_load)
        wait_values = [snap.get("cpu_wait", 0.0) for snap in high_load]
        wait_support = sum(value >= TOP["wait_soft"] for value in wait_values) >= 2 or (
            len(wait_values) >= 2 and sum(wait_values) / len(wait_values) >= TOP["wait_soft"]
        )
        corroborated = low_idle or runnable or d_state or wait_support
        severity = "high" if load_max >= load_hard and corroborated else ("medium" if load_avg >= load_soft and corroborated else "")
        if severity:
            results.append(finding(
                "top-load-high", "top", "risk", severity, "系统负载持续偏高",
                peak["time"], "load1", ">=", load_hard if severity == "high" else load_soft,
                load_max if severity == "high" else load_avg,
                f"Load1 平均={load_avg:.2f}，峰值={load_max:.2f}，CPU={cpu_count or 'unknown'}，低 idle={low_idle}，运行队列={runnable}，iowait={wait_support}，D 状态={d_state}",
                {"cpu_count": cpu_count, "load_per_cpu_peak": load_max / cpu_count if cpu_count else 0, "runnable_threshold": runnable_threshold},
            ))
    return results


def sort_findings(findings: list[dict[str, Any]]):
    findings.sort(key=lambda item: (SEVERITY_RANK.get(item["severity"], 9), item["time"], item["rule_id"]))


def analyze(root: Path, command: str, start: datetime | None, end: datetime | None):
    grouped = discover(root)
    result = {
        "schema_version": 1,
        "rule_snapshot": SNAPSHOT,
        "input": str(root),
        "requested_window": {"start": iso(start), "end": iso(end)},
        "hosts": {},
        "errors": [],
    }
    if not grouped:
        result["errors"].append("no supported OSWbb iostat/meminfo/top/mpstat files found")
        return result
    for host, modules in sorted(grouped.items()):
        host_result = {"coverage": {}, "cpu_count": 0, "findings": [], "errors": []}
        for module in MODULES:
            host_result["coverage"][module] = coverage(modules.get(module, []), start, end)
            host_result["errors"].extend(host_result["coverage"][module].pop("errors"))
        cpu_count, cpu_errors = parse_cpu_count(modules.get("mpstat", []))
        host_result["cpu_count"] = cpu_count
        host_result["errors"].extend(cpu_errors)
        if command != "inventory":
            if command in ("all", "iostat"):
                snapshots, errors = parse_iostat(modules.get("iostat", []), start, end)
                host_result["errors"].extend(errors)
                host_result["findings"].extend(analyze_iostat(snapshots))
            if command in ("all", "meminfo"):
                snapshots, errors = parse_meminfo(modules.get("meminfo", []), start, end)
                host_result["errors"].extend(errors)
                host_result["findings"].extend(analyze_meminfo(snapshots))
            if command in ("all", "top"):
                snapshots, errors = parse_top(modules.get("top", []), start, end)
                host_result["errors"].extend(errors)
                host_result["findings"].extend(analyze_top(snapshots, cpu_count))
        sort_findings(host_result["findings"])
        result["hosts"][host] = host_result
    return result


def self_check():
    with tempfile.TemporaryDirectory(prefix="oswbb-self-check-") as tmp:
        root = Path(tmp)
        stamps = ("Fri Jul 24 10:00:00 CST 2026", "Fri Jul 24 10:00:05 CST 2026", "Fri Jul 24 10:00:10 CST 2026")
        iostat = []
        meminfo = []
        top = []
        for index, stamp in enumerate(stamps):
            iostat.extend([
                f"zzz ***{stamp}",
                "avg-cpu:  %user %nice %system %iowait %steal %idle",
                "1 0 5 25 0 69",
                "Device r/s w/s rkB/s wkB/s r_await w_await aqu-sz %util",
                f"nvme0n1 0 50 0 1000 0 {20 + index} 1.2 98",
            ])
            meminfo.extend([
                f"zzz ***{stamp}", "MemTotal: 1048576 kB", f"MemAvailable: {80000 - index * 10000} kB",
                "SwapTotal: 1048576 kB", "SwapFree: 800000 kB", "CommitLimit: 1048576 kB",
                "Committed_AS: 1100000 kB", "Slab: 10000 kB", "SUnreclaim: 5000 kB",
                "Dirty: 30000 kB", "Writeback: 10000 kB",
            ])
            top.extend([
                f"zzz ***{stamp}", "top - 10:00:00 up 1 day, load average: 5.0, 4.0, 3.0",
                "Tasks: 100 total, 8 running, 90 sleeping, 0 stopped, 2 zombie",
                "%Cpu(s): 20 us, 10 sy, 0 ni, 5 id, 25 wa, 0 hi, 0 si, 0 st",
                "PID USER PR NI VIRT RES SHR S %CPU %MEM TIME+ COMMAND",
                "123 root 20 0 1g 100m 10m D 60.0 10.0 00:01.00 blocked-worker",
            ])
        (root / "host_iostat_26.07.24.1000.dat").write_text("\n".join(iostat) + "\n", encoding="utf-8")
        (root / "host_meminfo_26.07.24.1000.dat").write_text("\n".join(meminfo) + "\n", encoding="utf-8")
        (root / "host_top_26.07.24.1000.dat").write_text("\n".join(top) + "\n", encoding="utf-8")
        (root / "host_mpstat_26.07.24.1000.dat").write_text("Linux host (8 CPU)\n", encoding="utf-8")
        result = analyze(root, "all", None, None)
        assert not result["errors"], result["errors"]
        host = result["hosts"]["host"]
        assert host["cpu_count"] == 8
        rules = {item["rule_id"] for item in host["findings"]}
        required = {"iostat-write-latency-nvme0n1", "meminfo-available", "meminfo-commit", "top-cpu-wait", "top-process-d-state"}
        assert required <= rules, (required - rules, rules)
        assert all(host["coverage"][module]["samples"] == 3 for module in ("iostat", "meminfo", "top"))
        return {"status": "PASS", "rules": sorted(rules), "cpu_count": host["cpu_count"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inventory", "all", "iostat", "meminfo", "top", "mpstat", "self-check"))
    parser.add_argument("path", nargs="?", help="OSWbb archive directory, log file, or tar archive")
    parser.add_argument("--start", help="YYYY-MM-DD HH:MM:SS (CST)")
    parser.add_argument("--end", help="YYYY-MM-DD HH:MM:SS (CST)")
    parser.add_argument("--output", help="write JSON to this file instead of stdout")
    args = parser.parse_args(argv)
    if bool(args.start) != bool(args.end):
        parser.error("--start and --end must be provided together")
    if args.command == "self-check":
        payload = self_check()
    else:
        if not args.path:
            parser.error("path is required")
        source = Path(args.path).expanduser()
        if not source.exists():
            parser.error(f"path does not exist: {source}")
        start, end = parse_window(args.start), parse_window(args.end)
        if start and end and start > end:
            parser.error("--start must not be after --end")
        try:
            with prepared_input(source) as root:
                payload = analyze(root, args.command, start, end)
                payload["input"] = str(source)
        except (OSError, tarfile.TarError, ValueError) as exc:
            payload = {"schema_version": 1, "rule_snapshot": SNAPSHOT, "input": str(source), "hosts": {}, "errors": [str(exc)]}
    rendered = json.dumps(payload, ensure_ascii=False, indent=2, default=lambda value: sorted(value) if isinstance(value, set) else str(value))
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    if args.command == "self-check":
        return 0
    host_errors = any(host.get("errors") for host in payload.get("hosts", {}).values())
    return 1 if payload.get("errors") or host_errors else 0


if __name__ == "__main__":
    sys.exit(main())
