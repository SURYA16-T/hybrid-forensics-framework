def calculate_ram_risk_score(telemetry: dict) -> None:
    """
    Calculates the Live RAM Risk Score and prints an Incident Response Triage Report.
    """
    # 1. Define Heuristic Rule Weights
    weights = {
        "CRIT_01": {"name": "Hidden Processes (psxview mismatch)", "points": 45},
        "CRIT_02": {"name": "Unbacked Executable Memory (malfind PAGE_EXECUTE_READWRITE)", "points": 45},
        "CRIT_03": {"name": "Process Hollowing / Replacement", "points": 45},
        "CRIT_04": {"name": "Kernel Callback Table Modification", "points": 45},
        
        "HIGH_01": {"name": "Suspicious Parent-Child Relationship", "points": 25},
        "HIGH_02": {"name": "Inline API Hooking / SSDT Modification", "points": 25},
        "HIGH_03": {"name": "Orphaned Threads (No DLL backing)", "points": 25},
        
        "MED_01": {"name": "System Binary Foreign Network Socket (netscan)", "points": 10},
        "MED_02": {"name": "Sudden Privilege Escalation to SYSTEM", "points": 10},
        "MED_03": {"name": "Cleared History Buffers (cmdscan/consoles tampering)", "points": 10}
    }

    # Map native rules to telemetry rule_ids
    rule_mapping = {
        "RWX_EXECUTABLE_MEMORY": "CRIT_02",
        "ANONYMOUS_RWX": "CRIT_02",
        "UNBACKED_EXECUTABLE_PAGE": "CRIT_02",
        "CREATEFILE_A_HOOK": "HIGH_02",
        "CREATEFILE_W_HOOK": "HIGH_02",
    }

    triggered_rules = []
    total_points = 0
    math_breakdown_parts = []

    # 2. Evaluate Telemetry Data
    for finding in telemetry.get("findings", []):
        # Support both native framework rules and standard rule_ids
        native_rule = finding.get("rule")
        rule_id = finding.get("rule_id", rule_mapping.get(native_rule))

        if rule_id in weights:
            rule_info = weights[rule_id]
            points = rule_info["points"]
            count = finding.get("count", 1)
            
            # Subtotal calculation for this heuristic
            subtotal = points * count
            total_points += subtotal
            
            evidence = finding.get("evidence")
            if not evidence:
                desc = finding.get("description", "")
                region = finding.get("region", "")
                evidence = desc or region or "No extra details provided."

            triggered_rules.append({
                "id": rule_id,
                "name": rule_info["name"],
                "points_per": points,
                "count": count,
                "subtotal": subtotal,
                "evidence": evidence
            })
            math_breakdown_parts.append(f"({points} pts * {count})")

    # 3. Apply Capping Formula: min(Sum, 100)
    final_score = min(total_points, 100)
    
    # 4. Map to Risk Tier & Action Path
    if final_score <= 15:
        tier, emoji, action = "Low", "🟢", "No action required. Normal system operation."
    elif final_score <= 45:
        tier, emoji, action = "Medium", "🟡", "Trigger automated deep memory scan & cross-reference disk artifacts."
    elif final_score <= 75:
        tier, emoji, action = "High", "🟠", "Network-isolate the endpoint immediately."
    else:
        tier, emoji, action = "Critical", "🔴", "Rootkit/Takeover verified. Execute full Incident Response playbook."

    # 5. Generate Recommendations
    if tier in ["High", "Critical"]:
        recommendation = "Isolate the host at the network layer to prevent lateral movement. Export a full physical memory dump (.raw/.dmp) for deep Volatility/YARA analysis and begin looking for persistent registry/scheduled task hooks."
    elif tier == "Medium":
        recommendation = "Review corresponding EDR process creation logs on the disk. Schedule a full system anti-malware sweep and monitor network sockets for persistent outbound beaconing."
    else:
        recommendation = "No malicious anomalies detected. Continue baseline monitoring."

    # 6. Format and Print the Structured Triage Report
    print("=" * 60)
    print("            LIVE RAM RISK SCORE TRIAGE REPORT            ")
    print("=" * 60)
    print(f"FINAL RISK SCORE: {final_score} / 100")
    print(f"RISK TIER       : {emoji} {tier.upper()}")
    print(f"IMMEDIATE ACTION: {action}\n")
    
    print("1. TRIGGERED HEURISTICS:")
    if not triggered_rules:
        print("  - None. No anomalies detected.")
    for rule in triggered_rules:
        print(f"  [{rule['id']}] {rule['name']} (Count: {rule['count']})")
        print(f"         Evidence: {rule['evidence']}")
    print()

    print("2. MATHEMATICAL BREAKDOWN:")
    if math_breakdown_parts:
        breakdown_str = " + ".join(math_breakdown_parts)
        if total_points > 100:
            print(f"  Calculation: {breakdown_str} = {total_points} points.")
            print(f"  Result: min({total_points}, 100) -> Final Score: {final_score}")
        else:
            print(f"  Calculation: {breakdown_str} = {final_score}")
    else:
        print("  Calculation: 0 (No heuristics triggered)")
    print()

    print("3. ANALYSTS RECOMMENDATIONS:")
    print(f"  {recommendation}")
    print("=" * 60)
