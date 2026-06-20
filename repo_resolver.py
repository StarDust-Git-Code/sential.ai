import os
import shutil
import subprocess
import tempfile
from pathlib import Path

def resolve_target(target: str, log_callback=None) -> str:
    """
    If target is a GitHub URL, clone it to a local temp directory.
    If target is a local path, return it as-is.
    Returns the resolved local path.
    """
    target = target.strip()
    
    # Detect GitHub/Git URLs
    if target.startswith("https://github.com/") or target.startswith("git@") or target.endswith(".git"):
        clone_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".sentinel_repos")
        
        # Extract repo name for a stable folder name
        repo_name = target.rstrip("/").split("/")[-1].replace(".git", "")
        repo_path = os.path.join(clone_dir, repo_name)
        
        # If already cloned, pull latest; otherwise clone fresh
        if os.path.exists(os.path.join(repo_path, ".git")):
            if log_callback:
                log_callback(f"[dim]Repository already cloned. Pulling latest changes...[/dim]\n")
            try:
                subprocess.run(
                    ["git", "-C", repo_path, "pull", "--ff-only"],
                    capture_output=True, text=True, timeout=60
                )
            except Exception:
                pass  # If pull fails, use existing clone
        else:
            if log_callback:
                log_callback(f"[dim]Cloning repository: {target}...[/dim]\n")
            os.makedirs(clone_dir, exist_ok=True)
            
            # Remove stale partial clone if exists
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
            
            try:
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", target, repo_path],
                    capture_output=True, text=True, timeout=120
                )
                if result.returncode != 0:
                    raise Exception(f"Git clone failed: {result.stderr}")
            except FileNotFoundError:
                raise Exception("Git is not installed or not in PATH. Please install Git to clone remote repositories.")
        
        if log_callback:
            log_callback(f"[green]✓ Repository ready at: {repo_path}[/green]\n")
        
        return repo_path
    
    # Local path — validate it exists
    if not os.path.exists(target):
        raise Exception(f"Target path does not exist: {target}")
    
    return target
