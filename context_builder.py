import os
from pathlib import Path

def build_project_context(target_dir: str) -> str:
    """Crawls the directory and concatenates source code files into a single context string."""
    target_path = Path(target_dir)
    if not target_path.exists():
        return f"Error: Path {target_dir} does not exist."
    if target_path.is_file():
        return _read_file(target_path)
        
    ignore_dirs = {'.git', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build', '.idea', '.vscode'}
    ignore_exts = {'.pyc', '.exe', '.dll', '.so', '.png', '.jpg', '.jpeg', '.pdf', '.zip', '.tar', '.gz', '.docx'}
    
    context_chunks = []
    
    for root, dirs, files in os.walk(target_path):
        # Mutate dirs in-place to skip ignored directories
        dirs[:] = [d for d in dirs if d not in ignore_dirs and not d.startswith('.')]
        
        for file in files:
            file_path = Path(root) / file
            if file_path.suffix.lower() in ignore_exts:
                continue
                
            content = _read_file(file_path)
            if content:
                rel_path = file_path.relative_to(target_path)
                context_chunks.append(f"--- File: {rel_path} ---\n{content}\n")
                
    return "\n".join(context_chunks)

def _read_file(file_path: Path) -> str:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        # Skip binary files that don't decode properly as UTF-8
        return ""
    except Exception:
        return ""
