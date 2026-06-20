import os
import google.generativeai as genai
import chromadb
from pathlib import Path
from key_manager import APIKeyManager

def build_rag_system(target_dir: str, key_manager: APIKeyManager, log_callback=None):
    if not key_manager.keys:
        raise ValueError("No API keys configured.")
    
    if log_callback: log_callback("[dim]Initializing ChromaDB for RAG...[/dim]\n")
    
    # Setup ChromaDB in memory
    chroma_client = chromadb.Client()
    collection_name = "codebase_context"
    try:
        chroma_client.delete_collection(name=collection_name)
    except:
        pass
    collection = chroma_client.create_collection(name=collection_name)
    
    summary_model_name = "gemini-3.1-flash-lite"
    embedding_model_name = "models/gemini-embedding-2"
    
    target_path = Path(target_dir)
    ignore_dirs = {'.git', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build', '.idea', '.vscode'}
    ignore_exts = {'.pyc', '.exe', '.dll', '.so', '.png', '.jpg', '.jpeg', '.pdf', '.zip', '.tar', '.gz', '.docx'}
    
    file_id = 0
    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in ignore_dirs and not d.startswith('.')]
        for file in files:
            file_path = Path(root) / file
            if file_path.suffix.lower() in ignore_exts:
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except:
                continue
                
            if not content.strip():
                continue
                
            rel_path = str(file_path.relative_to(target_path))
            
            if log_callback: log_callback(f"[dim]Vectorizing & summarizing {rel_path}...[/dim]\n")
            
            def summarize_func():
                model = genai.GenerativeModel(summary_model_name)
                resp = model.generate_content(f"Briefly summarize what this code does:\n\n{content}")
                return resp.text
            
            try:
                summary = key_manager.execute_with_retry(summarize_func)
            except Exception as e:
                summary = "Failed to summarize."
                
            doc_text = f"File: {rel_path}\nSummary: {summary}\nCode:\n{content}"
            
            def embed_func():
                return genai.embed_content(model=embedding_model_name, content=doc_text, task_type="retrieval_document")
                
            try:
                embed_resp = key_manager.execute_with_retry(embed_func)
                embedding = embed_resp['embedding']
                
                collection.add(
                    embeddings=[embedding],
                    documents=[doc_text],
                    metadatas=[{"source": rel_path}],
                    ids=[f"id_{file_id}"]
                )
                file_id += 1
            except Exception as e:
                if log_callback: log_callback(f"[red]Error embedding {rel_path}: {e}[/red]\n")
                
    return collection
