@echo off
echo Installing Python dependencies for RAG Service...
py -m pip install fastapi uvicorn pydantic requests faiss-cpu python-dotenv numpy rich

echo Starting RAG Service on port 8081...
rem Optional: set NVIDIA_API_KEY=YOUR_KEY to use high-performance NVIDIA NIM embeddings
py -m uvicorn rag_service.knowledge_service:app --host 127.0.0.1 --port 8081 --reload
