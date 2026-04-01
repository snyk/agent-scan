#!/usr/bin/env python3
"""
Generate a CSV file listing all MCP configuration paths by client and OS.
"""
import csv
import sys
from pathlib import Path

# Add src to path to import agent_scan modules
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent_scan.well_known_clients import (
    MACOS_WELL_KNOWN_CLIENTS,
    LINUX_WELL_KNOWN_CLIENTS,
    WINDOWS_WELL_KNOWN_CLIENTS,
)


def generate_csv(output_path: str) -> None:
    """Generate CSV file with MCP config locations and skills directories by client and OS."""
    rows = []
    
    # Process macOS clients
    for client in MACOS_WELL_KNOWN_CLIENTS:
        for path in client.mcp_config_paths:
            rows.append({
                "Client Name": client.name,
                "OS": "macOS",
                "Path Type": "MCP Config",
                "Path": path,
            })
        for path in client.skills_dir_paths:
            rows.append({
                "Client Name": client.name,
                "OS": "macOS",
                "Path Type": "Skills Directory",
                "Path": path,
            })
    
    # Process Linux clients
    for client in LINUX_WELL_KNOWN_CLIENTS:
        for path in client.mcp_config_paths:
            rows.append({
                "Client Name": client.name,
                "OS": "Linux",
                "Path Type": "MCP Config",
                "Path": path,
            })
        for path in client.skills_dir_paths:
            rows.append({
                "Client Name": client.name,
                "OS": "Linux",
                "Path Type": "Skills Directory",
                "Path": path,
            })
    
    # Process Windows clients
    for client in WINDOWS_WELL_KNOWN_CLIENTS:
        for path in client.mcp_config_paths:
            rows.append({
                "Client Name": client.name,
                "OS": "Windows",
                "Path Type": "MCP Config",
                "Path": path,
            })
        for path in client.skills_dir_paths:
            rows.append({
                "Client Name": client.name,
                "OS": "Windows",
                "Path Type": "Skills Directory",
                "Path": path,
            })
    
    # Write CSV file
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Client Name", "OS", "Path Type", "Path"])
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"Generated {output_path} with {len(rows)} entries")


if __name__ == "__main__":
    # Generate CSV in the root of the repository
    repo_root = Path(__file__).parent.parent
    output_file = repo_root / "mcp-cfg-locations-by-client-and-os.csv"
    generate_csv(str(output_file))
