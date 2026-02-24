"""
Red Team Lab — Flask Application
Port of the Next.js application to Python/Flask
"""

import os
import platform
import subprocess
import json

from flask import Flask, render_template, request, jsonify
from data import (
    SCENARIOS, CAMPAIGNS, THREAT_ACTORS,
    get_scenario_by_id, get_campaign_by_id, get_threat_actor_by_id
)

app = Flask(__name__)


# ---------- Page Routes ----------

@app.route("/")
def index():
    """Main dashboard — unified Threat Library view."""
    return render_template(
        "index.html",
        scenarios=SCENARIOS,
        campaigns=CAMPAIGNS,
        threat_actors=THREAT_ACTORS,
    )


@app.route("/scenario/<scenario_id>")
def scenario_detail(scenario_id):
    """Individual scenario execution page."""
    scenario = get_scenario_by_id(scenario_id)
    if not scenario:
        return "Scenario not found", 404
    return render_template("scenario.html", scenario=scenario)


@app.route("/campaign/<campaign_id>")
def campaign_detail(campaign_id):
    """Individual campaign execution page."""
    campaign = get_campaign_by_id(campaign_id)
    if not campaign:
        return "Campaign not found", 404

    # Resolve step IDs to full scenario objects
    resolved_steps = []
    for step_id in campaign["steps"]:
        s = get_scenario_by_id(step_id)
        resolved_steps.append(s if s else {"id": step_id, "name": step_id})

    return render_template(
        "campaign.html",
        campaign=campaign,
        resolved_steps=resolved_steps,
    )


# ---------- API Routes ----------

@app.route("/api/execute", methods=["POST"])
def api_execute():
    """Execute a PowerShell script.
    Direct port of src/app/api/execute/route.ts
    """
    try:
        body = request.get_json(force=True)
        script_path = body.get("scriptPath")
        c2_host = body.get("c2Host", "127.0.0.1")
        target_ip = body.get("targetIp", "192.168.1.10")
        params = body.get("params", {})
        parent_process = body.get("parentProcess", "")

        if not script_path:
            return jsonify({"error": "No script path provided"}), 400

        # Security: normalize and prevent path traversal
        safe_path = os.path.normpath(script_path)
        if safe_path.startswith(".."):
            return jsonify({"error": "Invalid script path"}), 400

        full_path = os.path.join(os.getcwd(), safe_path)

        # Parent Process Launcher wrapper
        valid_parents = ["WINWORD", "EXCEL", "OUTLOOK", "calc", "notepad",
                         "explorer", "mshta", "rundll32", "svchost"]
        if parent_process and parent_process in valid_parents:
            launcher_path = os.path.join(
                os.getcwd(), "scenarios", "launchers", "process_launcher.ps1"
            )
            param_string = f' -TargetScript "{full_path}" -ParentProcess "{parent_process}"'
            full_path = launcher_path
        else:
            # Build parameter string for PowerShell
            param_string = ""

        if isinstance(params, dict):
            for key, value in params.items():
                if value and isinstance(value, str):
                    safe_value = value.replace('"', '`"').replace("'", "''")
                    param_string += f' -{key} "{safe_value}"'

        # Determine platform
        is_windows = platform.system() == "Windows"

        if is_windows:
            command = f'powershell -NoProfile -ExecutionPolicy Bypass -File "{full_path}"{param_string}'
            shell_exec = True
        else:
            # Dev/Mac simulation: use pwsh if available, else simulate
            command = (
                f'if command -v pwsh &> /dev/null; then '
                f'pwsh -File "{full_path}"{param_string}; '
                f'else echo "Warning: Non-Windows Host. Simulated Success for: {safe_path}"; fi'
            )
            shell_exec = True

        env = {**os.environ, "C2_HOST": c2_host, "TARGET_IP": target_ip}

        print(f"[API] Executing: {full_path}{param_string} with C2: {c2_host}")

        result = subprocess.run(
            command,
            shell=shell_exec,
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )

        # Read script content for verbose output
        script_content = ""
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                script_content = f.read()
        except Exception:
            script_content = "# Failed to read script content."

        return jsonify({
            "success": True,
            "output": result.stdout,
            "error": result.stderr,
            "scriptContent": script_content,
        })

    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Script execution timed out (120s)"}), 500
    except Exception as e:
        print(f"Execution Error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# ---------- Data API (for JS to fetch) ----------

@app.route("/api/data/scenarios")
def api_scenarios():
    return jsonify(SCENARIOS)


@app.route("/api/data/campaigns")
def api_campaigns():
    return jsonify(CAMPAIGNS)


@app.route("/api/data/threat-actors")
def api_threat_actors():
    return jsonify(THREAT_ACTORS)


# ---------- Run ----------

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)
