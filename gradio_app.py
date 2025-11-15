"""
Simple Gradio App for Supply Chain Security Scanning
A simplified Python-only interface for the SecureChain AI platform.
"""

import gradio as gr
from typing import List

# Import backend modules
from backend import (
    ScanType,
    ScanStatus,
    scans_storage,
    vulnerabilities_storage,
    create_scan,
    get_scan,
    get_all_scans,
    update_scan_status,
    add_vulnerability,
    get_vulnerabilities_by_scan,
    update_vulnerability_with_cve_details,
    fetch_cve_details,
    check_trivy_installed,
    install_trivy,
    run_trivy_scan,
    parse_trivy_vulnerabilities,
    create_project,
    get_project,
    get_all_projects,
    assign_scan_to_project,
    get_scans_by_project,
    run_ai_analysis,
    get_ai_analyses_by_project,
)


# ============= Gradio Interface Functions =============


def trigger_scan(scan_type: str, target: str) -> str:
    """
    Trigger a new scan using actual Trivy

    Returns:
        status_message
    """
    if not scan_type:
        return "❌ Error: Please select a scan type."

    if not target or not target.strip():
        return "❌ Error: Please provide a target (repository URL, container image, file path, etc.)"

    try:
        # Validate scan type
        valid_types = ["git_repo", "container", "vm", "sbom", "k8s"]
        if scan_type not in valid_types:
            return f"❌ Error: Invalid scan type '{scan_type}'. Must be one of: {', '.join(valid_types)}"

        # Check if Trivy is available
        print("Checking Trivy installation...")
        if not check_trivy_installed():
            print("Trivy not found, installing...")
            if not install_trivy():
                return "❌ Error: Failed to install Trivy. Please ensure Docker is running and you have internet access."

        # Create scan record
        scan = create_scan(scan_type, target.strip())

        try:
            # Update scan status to running
            update_scan_status(scan["id"], ScanStatus.RUNNING.value)

            # Run actual Trivy scan
            print(f"Starting Trivy scan for {scan_type}: {target}")
            scan_result = run_trivy_scan(scan_type, target.strip())

            if not scan_result["success"]:
                update_scan_status(scan["id"], ScanStatus.FAILED.value)
                return f"❌ Scan failed: {scan_result['error']}\n\nScan ID: {scan['id']}\nStatus: Failed"

            # Parse vulnerabilities from Trivy output
            trivy_data = scan_result["data"]
            vulnerabilities = parse_trivy_vulnerabilities(
                trivy_data, scan["id"])

            # Store vulnerabilities
            for vuln in vulnerabilities:
                vulnerabilities_storage.append(vuln)

            # Update severity counts
            scan["critical_count"] = sum(
                1 for v in vulnerabilities if v["severity"] == "CRITICAL"
            )
            scan["high_count"] = sum(
                1 for v in vulnerabilities if v["severity"] == "HIGH"
            )
            scan["medium_count"] = sum(
                1 for v in vulnerabilities if v["severity"] == "MEDIUM"
            )
            scan["low_count"] = sum(
                1 for v in vulnerabilities if v["severity"] == "LOW"
            )
            scan["vulnerability_count"] = len(vulnerabilities)

            # Mark scan as completed and store original Trivy JSON
            update_scan_status(
                scan["id"],
                ScanStatus.COMPLETED.value,
                scan["vulnerability_count"],
                trivy_data,
            )

            # Build success message
            message = f"✅ Scan completed successfully!\n\n"
            message += f"Scan ID: {scan['id']}\n"
            message += f"Type: {scan['scan_type']}\n"
            message += f"Target: {scan['target']}\n"
            message += f"Status: {scan['status']}\n"
            message += f"Vulnerabilities found: {scan['vulnerability_count']}\n"
            message += f"  - Critical: {scan['critical_count']}\n"
            message += f"  - High: {scan['high_count']}\n"
            message += f"  - Medium: {scan['medium_count']}\n"
            message += f"  - Low: {scan['low_count']}"

            if scan["vulnerability_count"] == 0:
                message += "\n\nℹ️ No vulnerabilities found in this scan."

            print(f"Scan completed successfully: {scan['id']}")
            return message

        except Exception as e:
            # Mark scan as failed
            update_scan_status(scan["id"], ScanStatus.FAILED.value)
            print(f"Error during scan processing: {e}")
            return f"❌ Error during scan processing: {str(e)}\n\nScan ID: {scan['id']}\nStatus: Failed"

    except Exception as e:
        print(f"Error creating scan: {e}")
        return f"❌ Error creating scan: {str(e)}\n\nPlease check your inputs and try again."


def refresh_scan_list() -> List[List]:
    """
    Refresh and return scan list as table data

    Returns:
        List of lists for Gradio Dataframe
    """
    try:
        scans = get_all_scans()
        if not scans:
            return [["No scans yet", "", "", "", "", ""]]

        # Sort by started_at (newest first)
        try:
            scans_sorted = sorted(
                scans, key=lambda x: x.get("started_at", ""), reverse=True
            )
        except Exception:
            scans_sorted = scans

        table_data = []
        for scan in scans_sorted:
            try:
                scan_id = scan.get("id", "Unknown")
                scan_type = scan.get("scan_type", "Unknown")
                target = scan.get("target", "Unknown")
                status = scan.get("status", "Unknown")
                vuln_count = scan.get("vulnerability_count", 0)
                started_at = scan.get("started_at", "")

                # Format display values safely
                short_id = (
                    scan_id[:8] + "...") if len(scan_id) > 8 else scan_id
                truncated_target = (
                    target[:50] + "...") if len(target) > 50 else target
                formatted_time = (
                    started_at[:19]
                    if started_at and len(started_at) >= 19
                    else (started_at or "N/A")
                )

                table_data.append(
                    [
                        short_id,
                        scan_type,
                        truncated_target,
                        status,
                        str(vuln_count),
                        formatted_time,
                    ]
                )
            except Exception as e:
                # Skip malformed scans
                continue

        if not table_data:
            return [["No valid scans found", "", "", "", "", ""]]

        return table_data

    except Exception as e:
        return [[f"Error loading scans: {str(e)}", "", "", "", "", ""]]


def get_scan_vulnerabilities(scan_id: str) -> tuple:
    """
    Get vulnerabilities for a selected scan

    Returns:
        (vulnerability_table_data, info_message)
    """
    if not scan_id or not scan_id.strip():
        return [], "⚠️ Please select a scan from the dropdown above."

    try:
        # Find full scan ID if short ID was provided
        full_scan_id = None
        for scan in scans_storage:
            scan_id_str = scan.get("id", "")
            if scan_id_str == scan_id or scan_id_str.startswith(scan_id):
                full_scan_id = scan_id_str
                break

        if not full_scan_id:
            return (
                [],
                f"❌ Scan not found: {scan_id}\n\nPlease make sure the scan exists and try refreshing the dropdown.",
            )

        vulnerabilities = get_vulnerabilities_by_scan(full_scan_id)

        if not vulnerabilities:
            scan = get_scan(full_scan_id)
            if scan:
                status = scan.get("status", "Unknown")
                result_json = scan.get("result_json")
                has_raw_data = "Yes" if result_json else "No"
                return (
                    [],
                    f"ℹ️ No vulnerabilities found for scan {scan_id[:8]}...\nStatus: {status}\nRaw JSON available: {has_raw_data}\n\nThis scan may still be in progress or completed with no vulnerabilities.",
                )
            return [], f"❌ Scan not found: {scan_id}"

        # Format for table display
        table_data = []
        for vuln in vulnerabilities:
            try:
                cve_id = vuln.get("cve_id", "Unknown")
                pkg_name = vuln.get("package_name") or "N/A"
                pkg_version = vuln.get("package_version") or "N/A"
                severity = vuln.get("severity", "UNKNOWN")

                # Format scores safely
                cvss = vuln.get("cvss_score")
                cvss_str = f"{cvss:.2f}" if cvss is not None else "N/A"

                epss = vuln.get("epss_score")
                epss_str = f"{epss:.3f}" if epss is not None else "N/A"

                epss_percentile = vuln.get("epss_percentile")
                epss_percentile_str = (
                    f"{epss_percentile:.3f}" if epss_percentile is not None else "N/A"
                )

                epss_date = vuln.get("epss_date") or "N/A"

                table_data.append(
                    [
                        cve_id,
                        pkg_name,
                        pkg_version,
                        severity,
                        cvss_str,
                        epss_str,
                        epss_percentile_str,
                        epss_date,
                    ]
                )
            except Exception as e:
                # Skip malformed vulnerabilities
                continue

        if not table_data:
            return [], f"⚠️ Error formatting vulnerabilities for scan {scan_id[:8]}..."

        scan = get_scan(full_scan_id)
        info = f"✅ Found {len(vulnerabilities)} vulnerability/vulnerabilities"

        # Check if any vulnerabilities have CVE API details
        cve_details_count = sum(
            1 for v in vulnerabilities if v.get("cve_api_details"))

        if scan:
            target = scan.get("target", "Unknown")
            scan_type = scan.get("scan_type", "Unknown")
            result_json = scan.get("result_json")
            has_raw_data = "Yes" if result_json else "No"
            info += f"\n\nScan Details:\n- Target: {target}\n- Type: {scan_type}\n- Raw JSON available: {has_raw_data}\n- CVE API details: {cve_details_count} CVEs"

        return table_data, info

    except Exception as e:
        return (
            [],
            f"❌ Error retrieving vulnerabilities: {str(e)}\n\nPlease try again or select a different scan.",
        )


def get_scan_dropdown_options() -> List[str]:
    """Get list of scan IDs for dropdown"""
    try:
        scans = get_all_scans()
        if not scans:
            return []

        # Sort by started_at (newest first), handle missing dates
        try:
            sorted_scans = sorted(
                scans, key=lambda x: x.get("started_at", ""), reverse=True
            )
        except Exception:
            sorted_scans = scans

        return [scan.get("id", "") for scan in sorted_scans if scan.get("id")]
    except Exception:
        return []


def get_raw_json_dropdown_options() -> List[str]:
    """Get list of scan IDs and CVE IDs with API details for raw JSON dropdown"""
    try:
        options = []

        # Add scan IDs
        scans = get_all_scans()
        if scans:
            try:
                sorted_scans = sorted(
                    scans, key=lambda x: x.get("started_at", ""), reverse=True
                )
            except Exception:
                sorted_scans = scans

            for scan in sorted_scans:
                scan_id = scan.get("id")
                if scan_id:
                    options.append(f"Scan: {scan_id[:8]}...")

        # Add CVE IDs that have API details
        cve_ids = []
        for vuln in vulnerabilities_storage:
            cve_id = vuln.get("cve_id")
            if cve_id and vuln.get("cve_api_details") and cve_id not in cve_ids:
                cve_ids.append(cve_id)

        if cve_ids:
            options.append("--- CVE IDs ---")
            options.extend(cve_ids)

        return options if options else []
    except Exception:
        return []


def get_scan_raw_json(selected_option: str) -> str:
    """
    Get the raw Trivy JSON output for a scan or CVE API details

    Returns:
        JSON string or error message
    """
    if not selected_option or not selected_option.strip():
        return "⚠️ Please select an option from the dropdown above."

    try:
        import json

        # Check if it's a CVE ID
        if selected_option.upper().startswith("CVE"):
            # Look for CVE API details in vulnerabilities
            cve_id = selected_option.strip().upper()
            if not cve_id.startswith("CVE-"):
                cve_id = f"CVE-{cve_id}"

            for vuln in vulnerabilities_storage:
                if vuln.get("cve_id") == cve_id and vuln.get("cve_api_details"):
                    # Pretty-print the CVE API JSON
                    try:
                        formatted_json = json.dumps(
                            vuln["cve_api_details"], indent=2, ensure_ascii=False
                        )
                        return (
                            f"🔍 Raw CVE API JSON for {cve_id}...\n\n{formatted_json}"
                        )
                    except Exception:
                        return f"🔍 Raw CVE API JSON for {cve_id}...\n\n{vuln['cve_api_details']}"

            return f"ℹ️ No CVE API details available for {cve_id}.\n\nTry fetching CVE details first using the 'Get CVE Details' button in the Vulnerabilities tab."

        # Check if it's a scan option (starts with "Scan: ")
        elif selected_option.startswith("Scan: "):
            # Extract scan ID from "Scan: abc123..."
            scan_display = selected_option[6:]  # Remove "Scan: " prefix
            scan_id = scan_display.replace(
                "...", "")  # Remove "..." if present

            # Find full scan ID
            full_scan_id = None
            for scan in scans_storage:
                scan_id_str = scan.get("id", "")
                if scan_id_str.startswith(scan_id):
                    full_scan_id = scan_id_str
                    break

            if not full_scan_id:
                return f"❌ Scan not found: {scan_id}"

            scan = get_scan(full_scan_id)
            if not scan:
                return f"❌ Scan not found: {scan_id}"

            result_json = scan.get("result_json")
            if not result_json:
                status = scan.get("status", "Unknown")
                return f"ℹ️ No raw JSON data available for scan {scan_id}...\n\nStatus: {status}\n\nRaw JSON data is only available for completed scans."

            # Pretty-print the JSON
            try:
                formatted_json = json.dumps(
                    result_json, indent=2, ensure_ascii=False)
                return f"✅ Raw Trivy JSON for scan {scan_id}...\n\n{formatted_json}"
            except Exception:
                return f"✅ Raw Trivy JSON for scan {scan_id}...\n\n{result_json}"

        else:
            return f"❌ Invalid selection: {selected_option}"

    except Exception as e:
        return f"❌ Error retrieving raw JSON: {str(e)}"


# ============= Gradio UI Components =============


def create_scan_tab():
    """Create the scan creation tab"""
    with gr.Column():
        gr.Markdown("## Create New Scan")
        gr.Markdown(
            "Select a scan type and provide the target to scan for vulnerabilities."
        )

        scan_type = gr.Dropdown(
            choices=["git_repo", "container", "vm", "sbom", "k8s"],
            label="Scan Type",
            value="container",
            info="Select the type of target to scan",
        )

        target_input = gr.Textbox(
            label="Target",
            placeholder="e.g., nginx:latest, https://github.com/user/repo, /path/to/sbom.json",
            info="Repository URL, container image name, file path, or Kubernetes cluster",
        )

        submit_btn = gr.Button("Start Scan", variant="primary")

        status_output = gr.Textbox(
            label="Status",
            lines=10,
            interactive=False,
            placeholder="Scan results will appear here...",
        )

        submit_btn.click(
            fn=trigger_scan, inputs=[scan_type,
                                     target_input], outputs=status_output
        )


def create_scan_list_tab():
    """Create the scan list tab"""
    with gr.Column():
        gr.Markdown("## All Scans")
        gr.Markdown("View all security scans that have been performed.")

        refresh_btn = gr.Button("Refresh List", variant="secondary")

        scan_table = gr.Dataframe(
            headers=["Scan ID", "Type", "Target",
                     "Status", "Vulns", "Started At"],
            label="Scans",
            interactive=False,
            wrap=True,
            value=refresh_scan_list(),  # Initial load
        )

        refresh_btn.click(fn=refresh_scan_list, outputs=scan_table)


def create_vulnerability_tab():
    """Create the vulnerability viewing tab"""
    with gr.Column():
        gr.Markdown("## View Vulnerabilities")
        gr.Markdown(
            "Select a scan to view its discovered vulnerabilities. Click on CVE IDs to see detailed information."
        )

        scan_dropdown = gr.Dropdown(
            choices=get_scan_dropdown_options(),
            label="Select Scan",
            info="Choose a scan to view its vulnerabilities",
        )

        refresh_dropdown_btn = gr.Button(
            "Refresh Scan List", variant="secondary", size="sm"
        )

        view_btn = gr.Button("View Vulnerabilities", variant="primary")

        info_output = gr.Textbox(
            label="Scan Information", lines=3, interactive=False)

        vuln_table = gr.Dataframe(
            headers=[
                "CVE ID",
                "Package",
                "Version",
                "Severity",
                "CVSS Score",
                "EPSS Score",
                "EPSS Percentile",
                "EPSS Date",
            ],
            label="Vulnerabilities",
            interactive=False,
            wrap=True,
        )

        # CVE Details Section
        with gr.Row():
            cve_input = gr.Textbox(
                label="CVE ID for Details",
                placeholder="e.g., CVE-2025-38664",
                info="Enter CVE ID to fetch detailed information",
            )
            fetch_cve_btn = gr.Button("Get CVE Details", variant="secondary")

        cve_details_output = gr.Textbox(
            label="CVE Details",
            lines=15,
            interactive=False,
            placeholder="CVE details will appear here...",
        )

        def update_dropdown():
            """Update dropdown choices"""
            try:
                choices = get_scan_dropdown_options()
                return gr.Dropdown(
                    choices=choices, value=choices[0] if choices else None
                )
            except Exception:
                return gr.Dropdown(choices=[])

        def view_vulns(scan_id):
            """View vulnerabilities and update dropdown"""
            try:
                table_data, info = get_scan_vulnerabilities(scan_id)
                choices = get_scan_dropdown_options()
                return (
                    table_data,
                    info,
                    gr.Dropdown(
                        choices=choices,
                        value=(
                            scan_id
                            if scan_id in choices
                            else (choices[0] if choices else None)
                        ),
                    ),
                )
            except Exception as e:
                return (
                    [],
                    f"❌ Error: {str(e)}",
                    gr.Dropdown(choices=get_scan_dropdown_options()),
                )

        def fetch_cve_info(cve_id: str):
            """Fetch CVE details and store raw data"""
            if not cve_id or not cve_id.strip():
                return "⚠️ Please enter a valid CVE ID (e.g., CVE-2025-38664)"

            try:
                # Clean up CVE ID
                cve_id = cve_id.strip().upper()
                if not cve_id.startswith("CVE-"):
                    cve_id = f"CVE-{cve_id}"

                result = fetch_cve_details(cve_id)

                if result["success"]:
                    # Store raw CVE API data in vulnerabilities
                    update_vulnerability_with_cve_details(
                        cve_id, result["data"])

                    # Return success message
                    return f"✅ CVE details fetched and stored successfully for {cve_id}.\n\nRaw JSON data is now available in the 'Raw JSON' tab."
                else:
                    return f"❌ Failed to fetch CVE details:\n\n{result['error']}\n\n💡 Make sure CVEDETAILS_API_KEY is set in .env file."

            except Exception as e:
                return f"❌ Error fetching CVE details: {str(e)}"

        refresh_dropdown_btn.click(fn=update_dropdown, outputs=scan_dropdown)

        view_btn.click(
            fn=view_vulns,
            inputs=scan_dropdown,
            outputs=[vuln_table, info_output, scan_dropdown],
        )

        fetch_cve_btn.click(
            fn=fetch_cve_info, inputs=cve_input, outputs=cve_details_output
        )


def create_raw_json_tab():
    """Create the raw JSON tab"""
    with gr.Column():
        gr.Markdown("## Raw Trivy JSON")
        gr.Markdown(
            "View the original JSON output from Trivy scans. This contains the complete scan results including all metadata."
        )

        raw_json_dropdown = gr.Dropdown(
            choices=get_raw_json_dropdown_options(),
            label="Select Scan or CVE",
            info="Choose a scan to view Trivy JSON or CVE ID to view API details",
        )

        refresh_raw_dropdown_btn = gr.Button(
            "Refresh Scan List", variant="secondary", size="sm"
        )

        view_raw_btn = gr.Button("View Raw JSON", variant="primary")

        raw_json_output = gr.Textbox(
            label="Raw Trivy JSON",
            lines=20,
            interactive=False,
            placeholder="Raw JSON output will appear here...",
        )

        copy_json_btn = gr.Button(
            "Copy JSON to Clipboard", variant="secondary", visible=False
        )

        def update_raw_dropdown():
            """Update dropdown choices"""
            try:
                choices = get_raw_json_dropdown_options()
                return gr.Dropdown(
                    choices=choices, value=choices[0] if choices else None
                )
            except Exception:
                return gr.Dropdown(choices=[])

        def view_raw_json(scan_id):
            """View raw JSON for selected scan"""
            try:
                json_content = get_scan_raw_json(scan_id)
                choices = get_scan_dropdown_options()
                # Show copy button if we have valid JSON
                show_copy = "✅ Raw Trivy JSON" in json_content
                return (
                    json_content,
                    gr.Dropdown(
                        choices=choices,
                        value=(
                            scan_id
                            if scan_id in choices
                            else (choices[0] if choices else None)
                        ),
                    ),
                    gr.Button(visible=show_copy),
                )
            except Exception as e:
                return (
                    f"❌ Error: {str(e)}",
                    gr.Dropdown(choices=get_scan_dropdown_options()),
                    gr.Button(visible=False),
                )

        def copy_json_to_clipboard(scan_id):
            """Return JSON content for copying (Gradio will handle clipboard)"""
            try:
                json_content = get_scan_raw_json(scan_id)
                if "✅ Raw Trivy JSON" in json_content:
                    # Extract just the JSON part
                    json_start = json_content.find("\n\n")
                    if json_start != -1:
                        json_data = json_content[json_start + 2:]
                        return json_data
                return "No JSON data available"
            except Exception:
                return "Error retrieving JSON data"

        refresh_raw_dropdown_btn.click(
            fn=update_raw_dropdown, outputs=raw_json_dropdown
        )

        view_raw_btn.click(
            fn=view_raw_json,
            inputs=raw_json_dropdown,
            outputs=[raw_json_output, raw_json_dropdown, copy_json_btn],
        )

        copy_json_btn.click(
            fn=copy_json_to_clipboard,
            inputs=raw_json_dropdown,
            outputs=None,  # Gradio handles clipboard copy
        )


def create_ai_analysis_tab():
    """Create the AI analysis tab"""
    with gr.Column():
        gr.Markdown("## AI Analysis")
        gr.Markdown(
            "Use AI agents to analyze vulnerability scan data. Create projects, assign scans, and get intelligent insights."
        )

        # Project Management Section
        with gr.Row():
            with gr.Column(scale=2):
                gr.Markdown("### Project Management")

                project_name_input = gr.Textbox(
                    label="Project Name",
                    placeholder="e.g., my-web-app, production-backend",
                    info="Enter a name for your project"
                )

                create_project_btn = gr.Button(
                    "Create Project", variant="primary")
                create_project_status = gr.Textbox(
                    label="Status",
                    lines=2,
                    interactive=False,
                    placeholder="Project creation status will appear here..."
                )

        with gr.Row():
            with gr.Column(scale=2):
                gr.Markdown("### Assign Scan to Project")

                project_dropdown = gr.Dropdown(
                    choices=[],
                    label="Select Project",
                    info="Choose a project to assign scans to"
                )

                scan_dropdown = gr.Dropdown(
                    choices=[],
                    label="Select Scan",
                    info="Choose a scan to assign to the project"
                )

                refresh_scan_dropdown_btn = gr.Button(
                    "Refresh Scan List", variant="secondary", size="sm")
                assign_scan_btn = gr.Button("Assign Scan", variant="secondary")
                assign_scan_status = gr.Textbox(
                    label="Status",
                    lines=2,
                    interactive=False,
                    placeholder="Assignment status will appear here..."
                )

        # AI Analysis Section
        with gr.Row():
            with gr.Column(scale=2):
                gr.Markdown("### Run AI Analysis")

                analysis_project_dropdown = gr.Dropdown(
                    choices=[],
                    label="Select Project for Analysis",
                    info="Choose a project to analyze"
                )

                analysis_scans_checkbox = gr.CheckboxGroup(
                    choices=[],
                    label="Select Scans to Analyze",
                    info="Select one or more scans to analyze (leave empty to analyze all scans in the project)",
                    visible=False
                )

                run_analysis_btn = gr.Button(
                    "Run AI Analysis", variant="primary")
                analysis_status = gr.Textbox(
                    label="Analysis Status",
                    lines=3,
                    interactive=False,
                    placeholder="Analysis status will appear here..."
                )

        # Analysis Results Section
        with gr.Row():
            with gr.Column():
                gr.Markdown("### Analysis Results")

                results_project_dropdown = gr.Dropdown(
                    choices=[],
                    label="Select Project to View Results",
                    info="Choose a project to view previous analysis results"
                )

                view_results_btn = gr.Button(
                    "View Results", variant="secondary")

        with gr.Row():
            prioritization_output = gr.Textbox(
                label="Prioritization Analysis",
                lines=10,
                interactive=False,
                placeholder="Prioritization analysis results will appear here..."
            )

        with gr.Row():
            supply_chain_output = gr.Textbox(
                label="Supply Chain Analysis",
                lines=10,
                interactive=False,
                placeholder="Supply chain analysis results will appear here..."
            )

        with gr.Row():
            remediation_output = gr.Textbox(
                label="Remediation Guidance",
                lines=10,
                interactive=False,
                placeholder="Remediation guidance will appear here..."
            )

        # Helper functions for UI
        def update_project_dropdowns():
            """Update all project dropdowns"""
            projects = get_all_projects()
            project_names = [p.get("name") for p in projects if p.get("name")]
            return (
                gr.Dropdown(choices=project_names),
                gr.Dropdown(choices=project_names),
                gr.Dropdown(choices=project_names),
            )

        def update_scan_dropdown():
            """Update scan dropdown"""
            scans = get_all_scans()
            scan_options = [
                f"{s.get('id', '')[:8]}... - {s.get('target', 'Unknown')[:50]}" for s in scans if s.get("id")]
            return gr.Dropdown(choices=scan_options, value=scan_options[0] if scan_options else None)

        def create_project_handler(project_name: str):
            """Handle project creation"""
            projects = get_all_projects()
            project_names = [p.get("name") for p in projects if p.get("name")]

            if not project_name or not project_name.strip():
                return (
                    "❌ Error: Please enter a project name.",
                    gr.Dropdown(choices=project_names),
                    gr.Dropdown(choices=project_names),
                    gr.Dropdown(choices=project_names),
                )

            project_name = project_name.strip()
            project = create_project(project_name)

            # Refresh project list
            projects = get_all_projects()
            project_names = [p.get("name") for p in projects if p.get("name")]

            if project.get("name") == project_name:
                return (
                    f"✅ Project '{project_name}' created successfully!",
                    gr.Dropdown(choices=project_names),
                    gr.Dropdown(choices=project_names),
                    gr.Dropdown(choices=project_names),
                )
            else:
                return (
                    f"ℹ️ Project '{project_name}' already exists.",
                    gr.Dropdown(choices=project_names),
                    gr.Dropdown(choices=project_names),
                    gr.Dropdown(choices=project_names),
                )

        def assign_scan_handler(project_name: str, scan_display: str):
            """Handle scan assignment"""
            projects = get_all_projects()
            project_names = [p.get("name") for p in projects if p.get("name")]

            if not project_name:
                return (
                    "❌ Error: Please select a project.",
                    gr.Dropdown(choices=project_names),
                    gr.Dropdown(choices=project_names),
                    gr.Dropdown(choices=project_names),
                )

            if not scan_display:
                return (
                    "❌ Error: Please select a scan.",
                    gr.Dropdown(choices=project_names),
                    gr.Dropdown(choices=project_names),
                    gr.Dropdown(choices=project_names),
                )

            # Extract scan_id from display string (format: "abc123... - target")
            try:
                scan_id_short = scan_display.split(" - ")[0].replace("...", "")
                # Find full scan_id
                full_scan_id = None
                for scan in scans_storage:
                    if scan.get("id", "").startswith(scan_id_short):
                        full_scan_id = scan.get("id")
                        break

                if not full_scan_id:
                    return (
                        "❌ Error: Scan not found.",
                        gr.Dropdown(choices=project_names),
                        gr.Dropdown(choices=project_names),
                        gr.Dropdown(choices=project_names),
                    )

                success = assign_scan_to_project(full_scan_id, project_name)

                # Refresh project list
                projects = get_all_projects()
                project_names = [p.get("name")
                                 for p in projects if p.get("name")]

                if success:
                    return (
                        f"✅ Scan assigned to project '{project_name}' successfully!",
                        gr.Dropdown(choices=project_names),
                        gr.Dropdown(choices=project_names),
                        gr.Dropdown(choices=project_names),
                    )
                else:
                    return (
                        f"❌ Error: Failed to assign scan to project.",
                        gr.Dropdown(choices=project_names),
                        gr.Dropdown(choices=project_names),
                        gr.Dropdown(choices=project_names),
                    )
            except Exception as e:
                return (
                    f"❌ Error: {str(e)}",
                    gr.Dropdown(choices=project_names),
                    gr.Dropdown(choices=project_names),
                    gr.Dropdown(choices=project_names),
                )

        def update_analysis_scans(project_name: str):
            """Update scan checkboxes when project is selected"""
            if not project_name:
                return gr.CheckboxGroup(choices=[], visible=False)

            scans = get_scans_by_project(project_name)
            if not scans:
                return gr.CheckboxGroup(choices=[], visible=False)

            # Create scan display options: "scan_id_short - target"
            scan_options = []
            scan_id_map = {}  # Map display string to full scan_id

            for scan in scans:
                scan_id = scan.get("id", "")
                target = scan.get("target", "Unknown")
                scan_display = f"{scan_id[:8]}... - {target[:50]}"
                scan_options.append(scan_display)
                scan_id_map[scan_display] = scan_id

            return gr.CheckboxGroup(choices=scan_options, visible=True)

        def run_analysis_handler(project_name: str, selected_scans: List[str]):
            """Handle AI analysis execution"""
            if not project_name:
                return (
                    "❌ Error: Please select a project.",
                    "",
                    "",
                    "",
                )

            # Convert selected scan display strings to scan IDs
            # If no scans selected (empty list), analyze all scans in the project
            selected_scan_ids = None
            if selected_scans and len(selected_scans) > 0:
                scans = get_scans_by_project(project_name)
                scan_id_map = {}
                for scan in scans:
                    scan_id = scan.get("id", "")
                    target = scan.get("target", "Unknown")
                    scan_display = f"{scan_id[:8]}... - {target[:50]}"
                    scan_id_map[scan_display] = scan_id

                selected_scan_ids = [scan_id_map.get(
                    display) for display in selected_scans if display in scan_id_map]
                # Remove None values
                selected_scan_ids = [sid for sid in selected_scan_ids if sid]

                if not selected_scan_ids:
                    return (
                        "❌ Error: No valid scans selected. Please select scans from the list.",
                        "",
                        "",
                        "",
                    )

            result = run_ai_analysis(project_name, selected_scan_ids)

            if result.get("success"):
                analysis = result.get("results", {})
                scan_count = len(
                    selected_scan_ids) if selected_scan_ids else "all"
                status_msg = f"✅ Analysis completed successfully!\n\nProject: {project_name}\nScans analyzed: {scan_count}\nAnalyzed at: {analysis.get('analyzed_at', 'N/A')}"
                return (
                    status_msg,
                    analysis.get("prioritization",
                                 "No prioritization analysis available."),
                    analysis.get("supply_chain",
                                 "No supply chain analysis available."),
                    analysis.get(
                        "remediation", "No remediation guidance available."),
                )
            else:
                error_msg = result.get("error", "Unknown error occurred.")
                return (
                    f"❌ Analysis failed: {error_msg}",
                    "",
                    "",
                    "",
                )

        def view_results_handler(project_name: str):
            """Handle viewing previous analysis results"""
            if not project_name:
                return (
                    "",
                    "",
                    "",
                )

            analyses = get_ai_analyses_by_project(project_name)

            if not analyses:
                return (
                    "ℹ️ No previous analyses found for this project.",
                    "",
                    "",
                )

            # Get the most recent analysis
            latest_analysis = analyses[0]

            return (
                latest_analysis.get(
                    "prioritization", "No prioritization analysis available."),
                latest_analysis.get(
                    "supply_chain", "No supply chain analysis available."),
                latest_analysis.get(
                    "remediation", "No remediation guidance available."),
            )

        # Event handlers
        create_project_btn.click(
            fn=create_project_handler,
            inputs=[project_name_input],
            outputs=[create_project_status, project_dropdown,
                     analysis_project_dropdown, results_project_dropdown]
        )

        refresh_scan_dropdown_btn.click(
            fn=update_scan_dropdown,
            outputs=[scan_dropdown]
        )

        assign_scan_btn.click(
            fn=assign_scan_handler,
            inputs=[project_dropdown, scan_dropdown],
            outputs=[assign_scan_status, project_dropdown,
                     analysis_project_dropdown, results_project_dropdown]
        )

        # Update scan checkboxes when project is selected
        analysis_project_dropdown.change(
            fn=update_analysis_scans,
            inputs=[analysis_project_dropdown],
            outputs=[analysis_scans_checkbox]
        )

        run_analysis_btn.click(
            fn=run_analysis_handler,
            inputs=[analysis_project_dropdown, analysis_scans_checkbox],
            outputs=[analysis_status, prioritization_output,
                     supply_chain_output, remediation_output]
        )

        view_results_btn.click(
            fn=view_results_handler,
            inputs=[results_project_dropdown],
            outputs=[prioritization_output,
                     supply_chain_output, remediation_output]
        )


# ============= Main App =============


def create_app():
    """Create and launch the Gradio app"""
    with gr.Blocks(
        title="SecureChain AI - Supply Chain Security", theme=gr.themes.Soft()
    ) as app:
        gr.Markdown(
            """
            # 🔒 SecureChain AI - Supply Chain Security Platform
            
            AI-powered software supply chain security analysis platform with comprehensive vulnerability scanning.
            """
        )

        with gr.Tabs():
            with gr.Tab("Create Scan"):
                create_scan_tab()

            with gr.Tab("Scan List"):
                create_scan_list_tab()

            with gr.Tab("Vulnerabilities"):
                create_vulnerability_tab()

            with gr.Tab("Raw JSON"):
                create_raw_json_tab()

            with gr.Tab("AI Analysis"):
                create_ai_analysis_tab()

        gr.Markdown(
            """
            ---
            **Note**: This is a simplified Gradio interface. For production use, connect to the full FastAPI backend.
            """
        )

    return app


if __name__ == "__main__":
    app = create_app()
    app.launch(server_name="0.0.0.0", server_port=7860, share=False)
