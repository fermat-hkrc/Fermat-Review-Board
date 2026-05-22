#!/usr/bin/env python3
"""
Comprehensive analysis of Fermat security scan results.
Reads all results.json files + scan_status.jsonl + poc data.
Outputs raw numbers for academic paper evaluation section.
"""

import json
import os
import glob
import sys
from collections import Counter, defaultdict
from pathlib import Path

BASE = "/home/cupcup/data/output/2026.05.16"

# ============================================================
# 1. LOAD ALL DATA
# ============================================================

def load_results():
    """Load all results.json from repo subdirectories."""
    repos = {}
    for rj in sorted(glob.glob(os.path.join(BASE, "*/results.json"))):
        repo_name = os.path.basename(os.path.dirname(rj))
        with open(rj) as f:
            repos[repo_name] = json.load(f)
    return repos

def load_scan_status():
    """Load scan_status.jsonl, keeping only the latest entry per repo."""
    path = os.path.join(BASE, "scan_status.jsonl")
    entries = {}
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                repo = entry["repo"]
                # Keep latest entry per repo (last line wins)
                entries[repo] = entry
    return entries

def load_poc_targets():
    """Load poc_targets.json."""
    path = os.path.join(BASE, "poc_targets.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {"findings": []}

def load_poc_verify_status():
    """Load poc_verify_status.jsonl, keeping final status per finding."""
    path = os.path.join(BASE, "poc_verify_status.jsonl")
    entries = {}
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                fid = entry["finding_id"]
                # Keep latest status per finding
                entries[fid] = entry
    return entries

# ============================================================
# 2. ANALYSIS
# ============================================================

def fmt_pct(num, denom):
    """Format percentage."""
    if denom == 0:
        return "N/A"
    return f"{100.0 * num / denom:.1f}%"

def fmt_num(n):
    """Format number with commas."""
    if isinstance(n, float):
        return f"{n:,.2f}"
    return f"{n:,}"

def section(title):
    width = 72
    print()
    print("=" * width)
    print(f"  {title}")
    print("=" * width)

def subsection(title):
    print()
    print(f"--- {title} ---")

def main():
    print("Loading data...")
    repos = load_results()
    scan_status = load_scan_status()
    poc_targets = load_poc_targets()
    poc_verify = load_poc_verify_status()

    # --------------------------------------------------------
    # SECTION: DATASET OVERVIEW
    # --------------------------------------------------------
    section("1. DATASET OVERVIEW")

    total_repos = len(repos)
    total_files = 0
    total_functions = 0
    total_call_edges = 0
    total_bytes = 0
    size_classes = Counter()

    for repo_name, data in repos.items():
        s = data.get("summary", {})
        cpg = s.get("cpg_stats", {})
        total_files += cpg.get("files", 0)
        total_functions += cpg.get("functions", 0)
        total_call_edges += cpg.get("call_edges", 0)
        ff = cpg.get("file_filter", {})
        total_bytes += ff.get("total_bytes", 0)
        sc = ff.get("size_class", "unknown")
        size_classes[sc] += 1

    print(f"  Total repos scanned (with results.json):  {fmt_num(total_repos)}")
    print(f"  Total C/C++ files analyzed:                {fmt_num(total_files)}")
    print(f"  Total functions in CPG:                    {fmt_num(total_functions)}")
    print(f"  Total call edges in CPG:                   {fmt_num(total_call_edges)}")
    print(f"  Total source bytes:                        {fmt_num(total_bytes)} ({total_bytes / (1024**2):.1f} MB)")

    subsection("Repo size distribution")
    for sc, cnt in sorted(size_classes.items(), key=lambda x: -x[1]):
        print(f"  {sc:>10s}: {cnt:>4d} repos  ({fmt_pct(cnt, total_repos)})")

    # --------------------------------------------------------
    # SECTION: TIMING
    # --------------------------------------------------------
    section("2. SCAN TIMING")

    elapsed_times = []
    elapsed_by_size = defaultdict(list)
    cpg_build_times = []
    cpg_total_build_times = []

    for repo_name, data in repos.items():
        s = data.get("summary", {})
        et = s.get("elapsed_seconds", 0)
        elapsed_times.append(et)
        cpg = s.get("cpg_stats", {})
        ff = cpg.get("file_filter", {})
        sc = ff.get("size_class", "unknown")
        elapsed_by_size[sc].append(et)
        bt = cpg.get("build_time_seconds", 0)
        if bt:
            cpg_build_times.append(bt)
        tbt = cpg.get("total_build_time", 0)
        if tbt:
            cpg_total_build_times.append(tbt)

    total_elapsed = sum(elapsed_times)
    avg_elapsed = total_elapsed / len(elapsed_times) if elapsed_times else 0
    elapsed_sorted = sorted(elapsed_times)
    median_elapsed = elapsed_sorted[len(elapsed_sorted)//2] if elapsed_sorted else 0

    print(f"  Total wall-clock time (all repos):   {fmt_num(total_elapsed)} seconds ({total_elapsed/3600:.1f} hours)")
    print(f"  Average time per repo:               {avg_elapsed:.1f} seconds")
    print(f"  Median time per repo:                {median_elapsed:.1f} seconds")
    print(f"  Min time:                            {min(elapsed_times):.1f} seconds")
    print(f"  Max time:                            {max(elapsed_times):.1f} seconds")

    # Percentiles
    for pct in [25, 50, 75, 90, 95, 99]:
        idx = int(len(elapsed_sorted) * pct / 100)
        idx = min(idx, len(elapsed_sorted) - 1)
        print(f"  P{pct:>2d}:                                  {elapsed_sorted[idx]:.1f} seconds")

    subsection("Elapsed time by repo size class")
    for sc in sorted(elapsed_by_size.keys()):
        times = elapsed_by_size[sc]
        avg = sum(times) / len(times) if times else 0
        ts = sorted(times)
        med = ts[len(ts)//2] if ts else 0
        mn = min(times) if times else 0
        mx = max(times) if times else 0
        print(f"  {sc:>10s}: n={len(times):>3d}  avg={avg:>8.1f}s  median={med:>8.1f}s  min={mn:>6.1f}s  max={mx:>8.1f}s")

    subsection("CPG build time")
    if cpg_build_times:
        avg_bt = sum(cpg_build_times) / len(cpg_build_times)
        bt_sorted = sorted(cpg_build_times)
        print(f"  Repos with CPG build time data:  {len(cpg_build_times)}")
        print(f"  Total CPG build time:            {sum(cpg_build_times):.1f} seconds")
        print(f"  Average CPG build time:          {avg_bt:.1f} seconds")
        print(f"  Median CPG build time:           {bt_sorted[len(bt_sorted)//2]:.1f} seconds")
        print(f"  Min CPG build time:              {min(cpg_build_times):.1f} seconds")
        print(f"  Max CPG build time:              {max(cpg_build_times):.1f} seconds")
    if cpg_total_build_times:
        avg_tbt = sum(cpg_total_build_times) / len(cpg_total_build_times)
        print(f"  Average total CPG build time:    {avg_tbt:.1f} seconds (incl. overhead)")
        print(f"  Total CPG build time (all):      {sum(cpg_total_build_times):.1f} seconds")

    # --------------------------------------------------------
    # SECTION: FUNNEL
    # --------------------------------------------------------
    section("3. ANALYSIS FUNNEL (L3 PIPELINE)")

    funnel_keys = ["l1_cpg", "l1_candidates", "after_dedup", "l3_graph_violations", "l3_spectra_confirmed", "final_violations"]
    funnel_totals = {k: 0 for k in funnel_keys}
    total_candidates_sum = 0
    confirmed_violations_sum = 0

    for repo_name, data in repos.items():
        s = data.get("summary", {})
        total_candidates_sum += s.get("total_candidates", 0)
        confirmed_violations_sum += s.get("confirmed_violations", 0)
        funnel = s.get("funnel", {})
        for k in funnel_keys:
            funnel_totals[k] += funnel.get(k, 0)

    print(f"  total_candidates (summary field):     {fmt_num(total_candidates_sum)}")
    print(f"  confirmed_violations (summary field):  {fmt_num(confirmed_violations_sum)}")
    print()

    funnel_labels = {
        "l1_cpg": "L1: Functions in CPG",
        "l1_candidates": "L1: Initial candidates",
        "after_dedup": "After deduplication",
        "l3_graph_violations": "L3: Graph violations",
        "l3_spectra_confirmed": "L3: Spectra confirmed",
        "final_violations": "Final violations",
    }

    prev_val = None
    for k in funnel_keys:
        val = funnel_totals[k]
        label = funnel_labels[k]
        pct_of_start = fmt_pct(val, funnel_totals["l1_candidates"]) if k != "l1_cpg" else ""
        reduction = ""
        if prev_val is not None and prev_val > 0:
            reduction = f"  (filtered {fmt_pct(prev_val - val, prev_val)} from prev stage)"
        print(f"  {label:<35s}  {val:>8,d}  {pct_of_start:>8s}{reduction}")
        prev_val = val

    # Overall reduction
    if funnel_totals["l1_candidates"] > 0:
        overall = funnel_totals["final_violations"] / funnel_totals["l1_candidates"] * 100
        print(f"\n  Overall pass-through rate: {overall:.2f}% of initial candidates become final violations")
        print(f"  Overall filter rate: {100 - overall:.2f}% of candidates filtered out")

    # --------------------------------------------------------
    # SECTION: VIOLATIONS BY PROPERTY TYPE
    # --------------------------------------------------------
    section("4. VIOLATIONS BY PROPERTY TYPE")

    by_property = Counter()
    for repo_name, data in repos.items():
        s = data.get("summary", {})
        bp = s.get("by_property", {})
        for prop, cnt in bp.items():
            by_property[prop] += cnt

    total_violations = sum(by_property.values())
    print(f"  Total violations: {fmt_num(total_violations)}")
    print()
    for prop, cnt in sorted(by_property.items(), key=lambda x: -x[1]):
        print(f"  {prop:<35s}  {cnt:>6,d}  ({fmt_pct(cnt, total_violations)})")

    # --------------------------------------------------------
    # SECTION: VIOLATIONS BY CONFIDENCE
    # --------------------------------------------------------
    section("5. VIOLATIONS BY CONFIDENCE LEVEL")

    by_confidence = Counter()
    for repo_name, data in repos.items():
        s = data.get("summary", {})
        bc = s.get("by_confidence", {})
        for conf, cnt in bc.items():
            by_confidence[conf] += cnt

    total_by_conf = sum(by_confidence.values())
    print(f"  Total violations: {fmt_num(total_by_conf)}")
    print()
    conf_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    for conf in conf_order:
        cnt = by_confidence.get(conf, 0)
        print(f"  {conf:<12s}  {cnt:>6,d}  ({fmt_pct(cnt, total_by_conf)})")
    # Any unlisted
    for conf, cnt in by_confidence.items():
        if conf not in conf_order:
            print(f"  {conf:<12s}  {cnt:>6,d}  ({fmt_pct(cnt, total_by_conf)})")

    # --------------------------------------------------------
    # SECTION: VIOLATIONS BY SEVERITY
    # --------------------------------------------------------
    section("6. VIOLATIONS BY SEVERITY")

    by_severity = Counter()
    for repo_name, data in repos.items():
        s = data.get("summary", {})
        bs = s.get("by_severity", {})
        for sev, cnt in bs.items():
            by_severity[sev] += cnt

    total_by_sev = sum(by_severity.values())
    print(f"  Total violations: {fmt_num(total_by_sev)}")
    print()
    for sev, cnt in sorted(by_severity.items(), key=lambda x: -x[1]):
        print(f"  {sev:<12s}  {cnt:>6,d}  ({fmt_pct(cnt, total_by_sev)})")

    # --------------------------------------------------------
    # SECTION: LLM STATS
    # --------------------------------------------------------
    section("7. LLM USAGE STATISTICS")

    total_llm_calls = 0
    total_input_tokens = 0
    total_output_tokens = 0
    total_cost_usd = 0.0
    total_successful = 0
    total_failed = 0
    llm_models = Counter()

    for repo_name, data in repos.items():
        s = data.get("summary", {})
        llm = s.get("llm_stats", {})
        total_llm_calls += llm.get("total_calls", 0)
        total_input_tokens += llm.get("total_input_tokens", 0)
        total_output_tokens += llm.get("total_output_tokens", 0)
        cost = llm.get("total_cost_usd", 0)
        if cost is not None and cost != float('inf'):
            total_cost_usd += cost
        total_successful += llm.get("successful", 0)
        total_failed += llm.get("failed", 0)
        model = llm.get("model", "unknown")
        if model:
            llm_models[model] += 1

    total_tokens = total_input_tokens + total_output_tokens
    avg_calls_per_repo = total_llm_calls / total_repos if total_repos else 0
    avg_cost_per_repo = total_cost_usd / total_repos if total_repos else 0

    print(f"  Total LLM calls:                     {fmt_num(total_llm_calls)}")
    print(f"    Successful:                        {fmt_num(total_successful)}")
    print(f"    Failed:                            {fmt_num(total_failed)}")
    print(f"    Failure rate:                      {fmt_pct(total_failed, total_llm_calls)}")
    print(f"  Average LLM calls per repo:          {avg_calls_per_repo:.1f}")
    print()
    print(f"  Total input tokens:                  {fmt_num(total_input_tokens)}")
    print(f"  Total output tokens:                 {fmt_num(total_output_tokens)}")
    print(f"  Total tokens:                        {fmt_num(total_tokens)}")
    print(f"  Avg input tokens per call:           {total_input_tokens / total_llm_calls:.0f}" if total_llm_calls else "")
    print(f"  Avg output tokens per call:          {total_output_tokens / total_llm_calls:.0f}" if total_llm_calls else "")
    print()
    print(f"  Total cost (USD):                    ${total_cost_usd:,.2f}")
    print(f"  Average cost per repo:               ${avg_cost_per_repo:,.2f}")
    print(f"  Cost per violation:                  ${total_cost_usd / total_violations:.2f}" if total_violations else "")
    print(f"  Cost per 1K tokens:                  ${total_cost_usd / (total_tokens / 1000):.4f}" if total_tokens else "")
    print()
    print(f"  LLM models used:")
    for model, cnt in llm_models.most_common():
        print(f"    {model}: {cnt} repos")

    # --------------------------------------------------------
    # SECTION: ENGINE CONTRIBUTION
    # --------------------------------------------------------
    section("8. ENGINE CONTRIBUTION AND CROSS-VALIDATION")

    # Analyze per-violation data
    total_v = 0
    graph_used = 0
    spectra_used = 0
    infer_used = 0
    ikos_used = 0

    confirmed_by_combos = Counter()
    graph_verdict_vals = Counter()
    spectra_verdict_vals = Counter()
    infer_verdict_vals = Counter()

    # Track engine participation
    confirmed_by_count = Counter()  # how many engines confirmed: 1, 2, 3

    for repo_name, data in repos.items():
        for v in data.get("violations", []):
            total_v += 1

            gv = v.get("graph_verdict", "")
            sv = v.get("spectra_verdict", "")
            iv = v.get("infer_verdict", "")
            cb = v.get("confirmed_by", [])

            graph_verdict_vals[gv] += 1
            spectra_verdict_vals[sv] += 1
            infer_verdict_vals[iv] += 1

            if gv:
                graph_used += 1
            if sv:
                spectra_used += 1
            if iv:
                infer_used += 1

            # confirmed_by analysis
            cb_tuple = tuple(sorted(cb))
            confirmed_by_combos[str(cb_tuple)] += 1
            confirmed_by_count[len(cb)] += 1

    print(f"  Total violations analyzed (per-violation data): {fmt_num(total_v)}")
    print()

    subsection("Engine participation (has non-empty verdict)")
    print(f"  Graph (Joern CPG):    {graph_used:>6,d} / {total_v:,d}  ({fmt_pct(graph_used, total_v)})")
    print(f"  Spectra (LLM):        {spectra_used:>6,d} / {total_v:,d}  ({fmt_pct(spectra_used, total_v)})")
    print(f"  Infer:                {infer_used:>6,d} / {total_v:,d}  ({fmt_pct(infer_used, total_v)})")

    subsection("Graph verdict distribution")
    for val, cnt in graph_verdict_vals.most_common():
        label = val if val else "(empty)"
        print(f"  {label:<20s}  {cnt:>6,d}  ({fmt_pct(cnt, total_v)})")

    subsection("Spectra verdict distribution")
    for val, cnt in spectra_verdict_vals.most_common():
        label = val if val else "(empty)"
        print(f"  {label:<20s}  {cnt:>6,d}  ({fmt_pct(cnt, total_v)})")

    subsection("Infer verdict distribution")
    for val, cnt in infer_verdict_vals.most_common():
        label = val if val else "(empty)"
        print(f"  {label:<20s}  {cnt:>6,d}  ({fmt_pct(cnt, total_v)})")

    subsection("confirmed_by combinations")
    for combo, cnt in confirmed_by_combos.most_common():
        print(f"  {combo:<35s}  {cnt:>6,d}  ({fmt_pct(cnt, total_v)})")

    subsection("Cross-validation depth (number of confirming engines)")
    for n in sorted(confirmed_by_count.keys()):
        cnt = confirmed_by_count[n]
        print(f"  {n} engine(s):  {cnt:>6,d}  ({fmt_pct(cnt, total_v)})")

    # --------------------------------------------------------
    # SECTION: CWE DISTRIBUTION
    # --------------------------------------------------------
    section("9. CWE DISTRIBUTION")

    cwe_counter = Counter()
    violations_with_cwe = 0
    violations_without_cwe = 0

    for repo_name, data in repos.items():
        for v in data.get("violations", []):
            cwes = v.get("cwe", [])
            if cwes:
                violations_with_cwe += 1
                for cwe in cwes:
                    cwe_counter[cwe] += 1
            else:
                violations_without_cwe += 1

    print(f"  Violations with CWE tags:    {fmt_num(violations_with_cwe)}")
    print(f"  Violations without CWE tags: {fmt_num(violations_without_cwe)}")
    print()
    print(f"  Top 20 CWEs:")
    for cwe, cnt in cwe_counter.most_common(20):
        print(f"    {cwe:<12s}  {cnt:>6,d}")

    # --------------------------------------------------------
    # SECTION: ERRORS & DEGRADED CAPABILITIES
    # --------------------------------------------------------
    section("10. ERRORS AND DEGRADED CAPABILITIES")

    repos_with_errors = 0
    total_errors = 0
    error_types = Counter()
    repos_with_degraded = 0
    degraded_caps = Counter()

    for repo_name, data in repos.items():
        s = data.get("summary", {})
        errors = s.get("errors", [])
        if errors:
            repos_with_errors += 1
            total_errors += len(errors)
            for err in errors:
                # Classify error
                err_str = str(err)
                if "timed out" in err_str.lower() or "timeout" in err_str.lower():
                    error_types["timeout"] += 1
                elif "CPGBuildError" in err_str or "cpg" in err_str.lower():
                    error_types["cpg_build_error"] += 1
                elif "LLM" in err_str or "llm" in err_str.lower():
                    error_types["llm_error"] += 1
                else:
                    error_types["other"] += 1

        dc = s.get("degraded_capabilities", [])
        if dc:
            repos_with_degraded += 1
            for cap in dc:
                degraded_caps[cap] += 1

    print(f"  Repos with errors:              {repos_with_errors} / {total_repos}  ({fmt_pct(repos_with_errors, total_repos)})")
    print(f"  Total error entries:            {total_errors}")
    print(f"  Repos with degraded caps:       {repos_with_degraded} / {total_repos}  ({fmt_pct(repos_with_degraded, total_repos)})")
    print()

    subsection("Error type breakdown")
    for etype, cnt in error_types.most_common():
        print(f"  {etype:<25s}  {cnt:>4d}")

    subsection("Degraded capabilities")
    if degraded_caps:
        for cap, cnt in degraded_caps.most_common():
            print(f"  {cap:<35s}  {cnt:>4d} repos")
    else:
        print("  No degraded capabilities reported in any repo.")

    # --------------------------------------------------------
    # SECTION: SCAN STATUS DATA
    # --------------------------------------------------------
    section("11. SCAN STATUS (from scan_status.jsonl)")

    done_entries = {r: e for r, e in scan_status.items() if e.get("status") == "done"}
    error_entries = {r: e for r, e in scan_status.items() if e.get("status") == "error" or e.get("error")}

    print(f"  Total entries in scan_status:        {len(scan_status)}")
    print(f"  Repos with status=done:              {len(done_entries)}")

    # Compute from scan_status
    ss_elapsed = [e["elapsed"] for e in done_entries.values() if e.get("elapsed")]
    ss_violations = [e.get("violations", 0) for e in done_entries.values()]
    ss_poc = [e.get("poc_triggered", 0) for e in done_entries.values()]

    if ss_elapsed:
        total_ss_elapsed = sum(ss_elapsed)
        print(f"  Total elapsed (scan_status):         {fmt_num(total_ss_elapsed)} seconds ({total_ss_elapsed/3600:.1f} hours)")
        print(f"  Average elapsed per repo:            {sum(ss_elapsed)/len(ss_elapsed):.1f} seconds")

    total_ss_violations = sum(ss_violations)
    total_ss_poc = sum(ss_poc)
    repos_with_violations = sum(1 for v in ss_violations if v > 0)
    repos_with_poc = sum(1 for p in ss_poc if p > 0)

    print(f"  Total violations (scan_status):      {fmt_num(total_ss_violations)}")
    print(f"  Repos with >= 1 violation:           {repos_with_violations} / {len(done_entries)}  ({fmt_pct(repos_with_violations, len(done_entries))})")
    print(f"  Total PoC triggered (scan_status):   {fmt_num(total_ss_poc)}")
    print(f"  Repos with >= 1 PoC:                 {repos_with_poc} / {len(done_entries)}  ({fmt_pct(repos_with_poc, len(done_entries))})")

    subsection("Scan status errors")
    error_repos_from_status = {r: e for r, e in scan_status.items() if e.get("error")}
    print(f"  Repos with error field set:          {len(error_repos_from_status)}")
    # Count timeout errors specifically
    timeout_repos = 0
    cpg_error_repos = 0
    spectra_timeout_repos = 0
    for r, e in error_repos_from_status.items():
        err = e.get("error", "")
        if "CPGBuildError" in err:
            cpg_error_repos += 1
        if "timed out" in err.lower() or "timeout" in err.lower():
            if "spectra" in err.lower():
                spectra_timeout_repos += 1
            else:
                timeout_repos += 1
    print(f"    CPG build errors:                  {cpg_error_repos}")
    print(f"    Spectra timeout errors:            {spectra_timeout_repos}")
    print(f"    Other timeout errors:              {timeout_repos}")

    # --------------------------------------------------------
    # SECTION: POC VERIFICATION
    # --------------------------------------------------------
    section("12. POC VERIFICATION")

    poc_findings = poc_targets.get("findings", [])
    print(f"  Total PoC targets:                   {len(poc_findings)}")

    # Analyze poc_targets
    poc_priorities = Counter()
    poc_repos = Counter()
    poc_confirmed_by = Counter()
    poc_cwes = Counter()

    for pf in poc_findings:
        poc_priorities[pf.get("priority", "unknown")] += 1
        poc_repos[pf.get("repo", "unknown")] += 1
        cb = tuple(sorted(pf.get("confirmed_by", [])))
        poc_confirmed_by[str(cb)] += 1
        for cwe in pf.get("cwe", []):
            poc_cwes[cwe] += 1

    subsection("PoC targets by priority")
    for pri, cnt in poc_priorities.most_common():
        print(f"  {pri}: {cnt}")

    subsection("PoC targets by confirming engines")
    for combo, cnt in poc_confirmed_by.most_common():
        print(f"  {combo}: {cnt}")

    subsection("PoC targets by CWE")
    for cwe, cnt in poc_cwes.most_common():
        print(f"  {cwe}: {cnt}")

    subsection("PoC targets by repo")
    for repo, cnt in poc_repos.most_common():
        print(f"  {repo}: {cnt}")

    # Analyze poc_verify_status
    subsection("PoC verification results (from poc_verify_status.jsonl)")
    print(f"  Total PoC verification entries (final per finding): {len(poc_verify)}")

    poc_statuses = Counter()
    poc_triggered_count = 0
    poc_not_triggered = 0
    poc_failed = 0
    poc_verify_elapsed = []

    for fid, entry in poc_verify.items():
        status = entry.get("status", "unknown")
        poc_statuses[status] += 1
        if entry.get("triggered"):
            poc_triggered_count += 1
        elapsed = entry.get("elapsed", 0)
        if elapsed:
            poc_verify_elapsed.append(elapsed)

    for status, cnt in poc_statuses.most_common():
        print(f"  {status:<20s}  {cnt:>4d}")

    print()
    print(f"  PoC triggered (verified true positive): {poc_triggered_count}")
    if poc_verify_elapsed:
        print(f"  Avg PoC verification time:              {sum(poc_verify_elapsed)/len(poc_verify_elapsed):.1f} seconds")
        print(f"  Total PoC verification time:            {sum(poc_verify_elapsed):.1f} seconds")

    # --------------------------------------------------------
    # SECTION: TOP REPOS
    # --------------------------------------------------------
    section("13. TOP REPOS BY VIOLATIONS")

    repo_violations = []
    for repo_name, data in repos.items():
        s = data.get("summary", {})
        v_count = s.get("confirmed_violations", 0)
        repo_violations.append((repo_name, v_count, s.get("elapsed_seconds", 0), s.get("total_candidates", 0)))

    repo_violations.sort(key=lambda x: -x[1])
    print(f"  {'Repo':<55s}  {'Violations':>10s}  {'Candidates':>10s}  {'Time(s)':>8s}")
    print(f"  {'-'*55}  {'-'*10}  {'-'*10}  {'-'*8}")
    for repo, vc, et, tc in repo_violations[:25]:
        print(f"  {repo:<55s}  {vc:>10,d}  {tc:>10,d}  {et:>8.1f}")

    # --------------------------------------------------------
    # SECTION: REPOS WITH ZERO VIOLATIONS
    # --------------------------------------------------------
    section("14. REPOS WITH ZERO VIOLATIONS")

    zero_repos = [r for r, vc, _, _ in repo_violations if vc == 0]
    nonzero_repos = [r for r, vc, _, _ in repo_violations if vc > 0]

    print(f"  Repos with 0 violations:              {len(zero_repos)} / {total_repos}  ({fmt_pct(len(zero_repos), total_repos)})")
    print(f"  Repos with >= 1 violation:            {len(nonzero_repos)} / {total_repos}  ({fmt_pct(len(nonzero_repos), total_repos)})")

    # Distribution of violation counts
    subsection("Violation count distribution")
    vc_counts = [vc for _, vc, _, _ in repo_violations]
    vc_sorted = sorted(vc_counts)
    for pct in [25, 50, 75, 90, 95, 99]:
        idx = int(len(vc_sorted) * pct / 100)
        idx = min(idx, len(vc_sorted) - 1)
        print(f"  P{pct:>2d}: {vc_sorted[idx]:>6,d} violations")
    print(f"  Max: {vc_sorted[-1]:>6,d} violations")
    print(f"  Mean: {sum(vc_counts)/len(vc_counts):>8.1f} violations per repo")

    # --------------------------------------------------------
    # SECTION: SPEC KIND DISTRIBUTION
    # --------------------------------------------------------
    section("15. SPEC KIND DISTRIBUTION (from violation data)")

    spec_kinds = Counter()
    property_codes = Counter()
    source_trust_vals = Counter()

    for repo_name, data in repos.items():
        for v in data.get("violations", []):
            spec_kinds[v.get("spec_kind", "unknown")] += 1
            property_codes[v.get("property_code", "unknown")] += 1
            source_trust_vals[v.get("source_trust", "unknown")] += 1

    subsection("Spec kind")
    for sk, cnt in spec_kinds.most_common():
        print(f"  {sk:<30s}  {cnt:>6,d}  ({fmt_pct(cnt, total_v)})")

    subsection("Property code")
    for pc, cnt in property_codes.most_common():
        print(f"  {pc:<10s}  {cnt:>6,d}  ({fmt_pct(cnt, total_v)})")

    subsection("Source trust")
    for st, cnt in source_trust_vals.most_common():
        print(f"  {st:<15s}  {cnt:>6,d}  ({fmt_pct(cnt, total_v)})")

    # --------------------------------------------------------
    # SECTION: EFFICIENCY METRICS
    # --------------------------------------------------------
    section("16. EFFICIENCY METRICS")

    print(f"  Violations per 1,000 functions:       {total_violations / (total_functions / 1000):.2f}" if total_functions else "")
    print(f"  Violations per 1,000 files:           {total_violations / (total_files / 1000):.2f}" if total_files else "")
    print(f"  Violations per repo (mean):           {total_violations / total_repos:.1f}")
    print(f"  Candidates per function:              {funnel_totals['l1_candidates'] / total_functions:.3f}" if total_functions else "")
    print(f"  Seconds per violation:                {total_elapsed / total_violations:.1f}" if total_violations else "")
    print(f"  Seconds per candidate:                {total_elapsed / total_candidates_sum:.2f}" if total_candidates_sum else "")
    print(f"  LLM calls per violation:              {total_llm_calls / total_violations:.1f}" if total_violations else "")
    print(f"  LLM calls per candidate:              {total_llm_calls / total_candidates_sum:.2f}" if total_candidates_sum else "")
    print(f"  Tokens per violation:                 {total_tokens / total_violations:.0f}" if total_violations else "")

    # --------------------------------------------------------
    # SECTION: SUMMARY TABLE (for paper)
    # --------------------------------------------------------
    section("17. SUMMARY TABLE (for paper)")

    print(f"  Metric                                     Value")
    print(f"  {'='*50}")
    print(f"  Repositories analyzed                       {total_repos}")
    print(f"  Source files                                {fmt_num(total_files)}")
    print(f"  Functions                                   {fmt_num(total_functions)}")
    print(f"  Source code size                            {total_bytes / (1024**2):.1f} MB")
    print(f"  Total scan time                            {total_elapsed/3600:.1f} hours")
    print(f"  Avg scan time per repo                     {avg_elapsed:.0f}s")
    print(f"  Initial candidates                         {fmt_num(funnel_totals['l1_candidates'])}")
    print(f"  After dedup                                {fmt_num(funnel_totals['after_dedup'])}")
    print(f"  Graph violations                           {fmt_num(funnel_totals['l3_graph_violations'])}")
    print(f"  Final violations                           {fmt_num(funnel_totals['final_violations'])}")
    print(f"  Filter rate                                {100 - (funnel_totals['final_violations']/funnel_totals['l1_candidates']*100):.1f}%" if funnel_totals['l1_candidates'] else "")
    print(f"  LLM calls                                  {fmt_num(total_llm_calls)}")
    print(f"  Total tokens                               {total_tokens/1e6:.1f}M")
    print(f"  Total cost                                 ${total_cost_usd:,.2f}")
    print(f"  PoC targets                                {len(poc_findings)}")
    print(f"  PoC triggered (verified)                   {poc_triggered_count}")
    if poc_findings:
        print(f"  PoC trigger rate                           {fmt_pct(poc_triggered_count, len(poc_findings))}")

    print("\n\n=== ANALYSIS COMPLETE ===")


if __name__ == "__main__":
    main()
