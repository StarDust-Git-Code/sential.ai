"""
SentinelAI — Interactive Audit Chat Engine
Allows follow-up questions after an audit using the already-built RAG index.
"""

import google.generativeai as genai
from google.api_core.exceptions import ResourceExhausted, InvalidArgument, NotFound
from typing import Iterator
from key_manager import APIKeyManager
import time


# Use Gemma 4 31B for chat — 15 RPM, 1.5K RPD, unlimited TPM
CHAT_MODELS = [
    "models/gemma-4-31b-it",
    "gemini-3.1-flash-lite",
]

CHAT_SYSTEM_PROMPT = """You are SentinelAI, an expert security auditor assistant. A comprehensive 6-phase security audit has just been completed on a codebase. The user is now asking follow-up questions.

Your role:
- Answer questions about the audited codebase with precision
- Reference specific files and line numbers when possible
- Explain vulnerability findings in more detail when asked
- Suggest concrete code fixes with code snippets
- Help prioritize remediation efforts
- Stay focused on security topics relevant to the audited code

Be concise but thorough. Use Markdown formatting for code blocks and tables."""


class AuditChatEngine:
    """Interactive Q&A engine that reuses the RAG index built during an audit."""
    
    def __init__(
        self,
        collection,
        raw_code: str,
        report: str,
        key_manager: APIKeyManager,
        history: list = None
    ):
        self.collection = collection
        self.raw_code = raw_code
        self.report = report
        self.key_manager = key_manager
        self.history = history or []
    
    def _retrieve_context(self, query: str, n_results: int = 5) -> str:
        """Retrieve relevant code chunks from ChromaDB for the question."""
        def retrieve_func():
            embed_resp = genai.embed_content(
                model="models/gemini-embedding-2",
                content=query,
                task_type="retrieval_query"
            )
            return self.collection.query(
                query_embeddings=[embed_resp['embedding']],
                n_results=n_results
            )
        
        try:
            results = self.key_manager.execute_with_retry(retrieve_func)
            if results and results['documents'] and results['documents'][0]:
                return "\n\n".join(results['documents'][0])
        except Exception:
            pass
        return "No relevant context retrieved."
    
    def _build_history_text(self) -> str:
        """Format conversation history for the prompt."""
        if not self.history:
            return "No prior conversation."
        
        lines = []
        for msg in self.history[-6:]:  # Keep last 3 exchanges to stay in context window
            role = "User" if msg["role"] == "user" else "SentinelAI"
            lines.append(f"**{role}:** {msg['content'][:500]}")
        return "\n".join(lines)
    
    def ask(self, question: str) -> Iterator[str]:
        """
        Ask a follow-up question about the audited codebase.
        Streams the response as text chunks.
        """
        # Retrieve relevant code for this specific question
        rag_context = self._retrieve_context(question)
        history_text = self._build_history_text()
        
        prompt = f"""{CHAT_SYSTEM_PROMPT}

### Audit Report Summary (for context):
{self.report[:4000]}

### Relevant Code from RAG Index:
{rag_context}

### Conversation History:
{history_text}

### User Question:
{question}

Answer concisely. Reference specific files and line numbers from the codebase."""

        # Try each model in the chain
        last_error = None
        for model_id in CHAT_MODELS:
            attempts = 0
            max_attempts = max(self.key_manager.count() * 2, 2)
            
            while attempts < max_attempts:
                try:
                    genai.configure(api_key=self.key_manager.get_current_key())
                    model = genai.GenerativeModel(model_id)
                    
                    response = model.generate_content(prompt, stream=True)
                    for chunk in response:
                        if chunk.text:
                            yield chunk.text
                    return
                    
                except (ResourceExhausted, NotFound) as e:
                    self.key_manager.rotate_key()
                    attempts += 1
                    time.sleep(1)
                    last_error = e
                except InvalidArgument as e:
                    last_error = e
                    break
                except Exception as e:
                    last_error = e
                    break
        
        yield f"\n[Error: Chat model failed — {last_error}]"
