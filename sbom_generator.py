"""
SentinelAI — SBOM (Software Bill of Materials) Generator
Generates CycloneDX-format SBOMs from project dependency manifests.
"""

import os
import re
import json
import uuid
from datetime import datetime, timezone
from typing import Optional


# Supported manifest files and their ecosystems
MANIFEST_FILES = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "requirements.txt": "pypi",
    "Pipfile.lock": "pypi",
    "pyproject.toml": "pypi",
    "setup.py": "pypi",
    "Gemfile.lock": "rubygems",
    "go.mod": "golang",
    "go.sum": "golang",
    "Cargo.lock": "cargo",
    "Cargo.toml": "cargo",
    "pom.xml": "maven",
    "build.gradle": "maven",
    "build.gradle.kts": "maven",
    "composer.json": "packagist",
    "pubspec.yaml": "pub",
    "pubspec.lock": "pub",
}


def _find_manifests(project_path: str) -> list:
    """Scan the project for dependency manifest files."""
    found = []
    for root, dirs, files in os.walk(project_path):
        # Skip node_modules, .venv, .git
        dirs[:] = [d for d in dirs if d not in (
            "node_modules", ".venv", "venv", ".git", "__pycache__",
            "dist", "build", ".next", ".sentinel_repos"
        )]
        for filename in files:
            if filename in MANIFEST_FILES:
                full_path = os.path.join(root, filename)
                rel_path = os.path.relpath(full_path, project_path)
                found.append({
                    "path": full_path,
                    "relative": rel_path,
                    "filename": filename,
                    "ecosystem": MANIFEST_FILES[filename],
                })
    return found


def _parse_package_json(filepath: str) -> list:
    """Parse npm package.json for dependencies."""
    components = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            pkg = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return components
    
    for dep_type in ("dependencies", "devDependencies", "peerDependencies"):
        deps = pkg.get(dep_type, {})
        for name, version in deps.items():
            # Clean version constraints (^, ~, >=, etc.)
            clean_version = re.sub(r'^[\^~>=<*]+', '', str(version)).strip()
            scope = "required" if dep_type == "dependencies" else "optional"
            
            components.append({
                "type": "library",
                "name": name,
                "version": clean_version,
                "purl": f"pkg:npm/{name}@{clean_version}",
                "ecosystem": "npm",
                "scope": scope,
                "source": os.path.basename(filepath),
            })
    
    return components


def _parse_requirements_txt(filepath: str) -> list:
    """Parse Python requirements.txt."""
    components = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except (FileNotFoundError, UnicodeDecodeError):
        return components
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        
        # Parse: package==version, package>=version, package
        match = re.match(r'^([a-zA-Z0-9_.-]+)\s*(?:[><=!~]+\s*(.+?))?(?:\s*;.*)?$', line)
        if match:
            name = match.group(1).strip()
            version = match.group(2).strip() if match.group(2) else "unspecified"
            # Take the first version if there are multiple constraints
            version = version.split(",")[0].strip()
            
            components.append({
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}@{version}",
                "ecosystem": "pypi",
                "scope": "required",
                "source": os.path.basename(filepath),
            })
    
    return components


def _parse_pyproject_toml(filepath: str) -> list:
    """Parse pyproject.toml for dependencies."""
    components = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        return components
    
    # Simple regex-based parsing (avoids toml dependency)
    dep_section = re.search(
        r'\[(?:project\.)?dependencies\]\s*\n(.*?)(?:\n\[|\Z)',
        content, re.DOTALL
    )
    
    if dep_section:
        for line in dep_section.group(1).strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r'"?([a-zA-Z0-9_.-]+)(?:[><=!~]+(.+?))?"?', line)
            if match:
                name = match.group(1)
                version = match.group(2) or "unspecified"
                clean_ver = version.strip().strip('"')
                components.append({
                    "type": "library",
                    "name": name,
                    "version": clean_ver,
                    "purl": f"pkg:pypi/{name}@{clean_ver}",
                    "ecosystem": "pypi",
                    "scope": "required",
                    "source": os.path.basename(filepath),
                })
    
    # Also check [project] dependencies list format
    deps_list = re.findall(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
    for dep_block in deps_list:
        for dep_str in re.findall(r'"([^"]+)"', dep_block):
            match = re.match(r'([a-zA-Z0-9_.-]+)(?:\s*[><=!~]+\s*(.+))?', dep_str)
            if match:
                name = match.group(1)
                version = match.group(2) or "unspecified"
                # Avoid duplicates
                if not any(c["name"] == name for c in components):
                    components.append({
                        "type": "library",
                        "name": name,
                        "version": version.strip(),
                        "purl": f"pkg:pypi/{name}@{version.strip()}",
                        "ecosystem": "pypi",
                        "scope": "required",
                        "source": os.path.basename(filepath),
                    })
    
    return components


def _parse_go_mod(filepath: str) -> list:
    """Parse Go go.mod for dependencies."""
    components = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        return components
    
    # Match require blocks and single requires
    require_block = re.findall(
        r'require\s+\((.*?)\)',
        content, re.DOTALL
    )
    
    for block in require_block:
        for line in block.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1]
                components.append({
                    "type": "library",
                    "name": name,
                    "version": version,
                    "purl": f"pkg:golang/{name}@{version}",
                    "ecosystem": "golang",
                    "scope": "required",
                    "source": "go.mod",
                })
    
    # Single-line requires
    for match in re.finditer(r'^require\s+(\S+)\s+(\S+)', content, re.MULTILINE):
        name = match.group(1)
        version = match.group(2)
        if not any(c["name"] == name for c in components):
            components.append({
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:golang/{name}@{version}",
                "ecosystem": "golang",
                "scope": "required",
                "source": "go.mod",
            })
    
    return components


def _parse_generic(filepath: str, ecosystem: str) -> list:
    """Generic fallback parser that extracts what it can."""
    components = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except (FileNotFoundError, UnicodeDecodeError):
        return components
    
    # Try to find version-like patterns
    patterns = [
        r'"([a-zA-Z0-9_.-]+)"\s*:\s*"([^"]+)"',           # JSON-style
        r'([a-zA-Z0-9_.-]+)\s*=\s*["\']?([0-9][^"\']*)',   # TOML/INI-style
    ]
    
    seen = set()
    for pattern in patterns:
        for match in re.finditer(pattern, content):
            name = match.group(1)
            version = match.group(2)
            if name not in seen and len(name) > 1:
                seen.add(name)
                components.append({
                    "type": "library",
                    "name": name,
                    "version": version,
                    "purl": f"pkg:{ecosystem}/{name}@{version}",
                    "ecosystem": ecosystem,
                    "scope": "required",
                    "source": os.path.basename(filepath),
                })
    
    return components


PARSERS = {
    "package.json": _parse_package_json,
    "requirements.txt": _parse_requirements_txt,
    "pyproject.toml": _parse_pyproject_toml,
    "go.mod": _parse_go_mod,
}


def generate_sbom(project_path: str, log_callback=None) -> dict:
    """
    Generate a CycloneDX 1.5 SBOM for the project.
    
    Returns the SBOM as a dict (CycloneDX JSON format).
    """
    manifests = _find_manifests(project_path)
    
    if log_callback:
        log_callback(f"[bold]Found {len(manifests)} manifest files[/bold]\n")
    
    all_components = []
    seen_purls = set()
    
    for manifest in manifests:
        if log_callback:
            log_callback(f"[dim]  Parsing {manifest['relative']} ({manifest['ecosystem']})...[/dim]\n")
        
        parser = PARSERS.get(manifest["filename"])
        if parser:
            components = parser(manifest["path"])
        else:
            components = _parse_generic(manifest["path"], manifest["ecosystem"])
        
        # Deduplicate by purl
        for comp in components:
            if comp["purl"] not in seen_purls:
                seen_purls.add(comp["purl"])
                all_components.append(comp)
    
    if log_callback:
        log_callback(f"[bold green]Total components: {len(all_components)}[/bold green]\n")
    
    # Build CycloneDX 1.5 BOM
    bom_serial = f"urn:uuid:{uuid.uuid4()}"
    
    cyclonedx_components = []
    for comp in all_components:
        cdx_comp = {
            "type": comp["type"],
            "name": comp["name"],
            "version": comp["version"],
            "purl": comp["purl"],
            "scope": comp["scope"],
            "properties": [
                {"name": "sentinelai:source", "value": comp["source"]},
                {"name": "sentinelai:ecosystem", "value": comp["ecosystem"]},
            ],
        }
        
        # Add external references for known ecosystems
        if comp["ecosystem"] == "npm":
            cdx_comp["externalReferences"] = [
                {"type": "website", "url": f"https://www.npmjs.com/package/{comp['name']}"}
            ]
        elif comp["ecosystem"] == "pypi":
            cdx_comp["externalReferences"] = [
                {"type": "website", "url": f"https://pypi.org/project/{comp['name']}/"}
            ]
        
        cyclonedx_components.append(cdx_comp)
    
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": bom_serial,
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "SentinelAI",
                        "version": "2.0",
                        "description": "AI-powered security auditing tool",
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": os.path.basename(os.path.abspath(project_path)),
                "version": "0.0.0",
            },
        },
        "components": cyclonedx_components,
    }
    
    return sbom


def save_sbom(sbom: dict, output_path: str = None) -> str:
    """Save the SBOM to a JSON file."""
    if output_path is None:
        output_path = "sentinel_sbom.json"
    
    output_path = os.path.abspath(output_path)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)
    
    return output_path


def format_sbom_summary(sbom: dict) -> str:
    """Format SBOM as a human-readable summary."""
    components = sbom.get("components", [])
    
    if not components:
        return "No dependencies found."
    
    # Group by ecosystem
    by_ecosystem = {}
    for comp in components:
        eco = "unknown"
        for prop in comp.get("properties", []):
            if prop["name"] == "sentinelai:ecosystem":
                eco = prop["value"]
                break
        by_ecosystem.setdefault(eco, []).append(comp)
    
    lines = []
    lines.append(f"SBOM: {len(components)} total components\n")
    
    for eco, comps in sorted(by_ecosystem.items()):
        lines.append(f"  {eco}: {len(comps)} packages")
        # Show scope breakdown
        required = sum(1 for c in comps if c.get("scope") == "required")
        optional = len(comps) - required
        if optional > 0:
            lines.append(f"    ({required} required, {optional} dev/optional)")
    
    lines.append("")
    lines.append(f"{'Package':>35} | {'Version':>15} | {'Ecosystem':>10}")
    lines.append("-" * 68)
    
    for comp in components[:30]:  # Limit display
        name = comp["name"][:35]
        version = comp["version"][:15]
        eco = "?"
        for prop in comp.get("properties", []):
            if prop["name"] == "sentinelai:ecosystem":
                eco = prop["value"][:10]
                break
        lines.append(f"{name:>35} | {version:>15} | {eco:>10}")
    
    if len(components) > 30:
        lines.append(f"  ... and {len(components) - 30} more")
    
    return "\n".join(lines)
