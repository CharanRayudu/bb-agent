import os
import threading
import requests
from typing import Optional, List, Union

try:
    from sentence_transformers import SentenceTransformer
except ImportError:
    SentenceTransformer = None

# --- Common Interface for Embedding Models ---

class BaseEmbedder:
    def encode(self, texts: List[str]) -> List[List[float]]:
        raise NotImplementedError
        
    def get_dimension(self) -> int:
        raise NotImplementedError

class LocalEmbedder(BaseEmbedder):
    def __init__(self, model_instance):
        self.model = model_instance
        
    def encode(self, texts: List[str]) -> List[List[float]]:
        # SentenceTransformer.encode returns numpy arrays or lists
        vecs = self.model.encode(texts, convert_to_numpy=True)
        return vecs.tolist()
        
    def get_dimension(self) -> int:
        return int(self.model.get_sentence_embedding_dimension())

class NVIDIAEmbedder(BaseEmbedder):
    """
    NVIDIA NIM Embedding API Support.
    Documentation: https://build.nvidia.com/nvidia/nv-embedqa-e5-v5
    """
    def __init__(self, api_key: str, model_name: str = "nvidia/nv-embedqa-e5-v5"):
        self.api_key = api_key
        self.model_name = model_name
        self.base_url = "https://integrate.api.nvidia.com/v1/embeddings"
        # nv-embedqa-e5-v5 has 1024 dimensions
        # snowflake/arctic-embed-l has 1024
        self.dimension = 1024 
        
    def encode(self, texts: List[str]) -> List[List[float]]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "input": texts,
            "model": self.model_name,
            "input_type": "query",
            "encoding_format": "float"
        }
        
        response = requests.post(self.base_url, headers=headers, json=payload)
        response.raise_for_status()
        
        data = response.json()
        # Sort by index to maintain consistency
        embeddings = sorted(data["data"], key=lambda x: x["index"])
        return [item["embedding"] for item in embeddings]
        
    def get_dimension(self) -> int:
        return self.dimension

# 全局模型实例
_global_model: Optional[BaseEmbedder] = None
_model_lock = threading.Lock()

def get_embedding_model(project_root: Optional[str] = None) -> Optional[BaseEmbedder]:
    """
    获取全局共享的句向量模型实例（线程安全）。
    优先使用 NVIDIA NIM (如果提供环境变量 NVIDIA_API_KEY)，否则回退到本地模型。
    """
    global _global_model

    if _global_model is not None:
        return _global_model

    with _model_lock:
        if _global_model is not None:
            return _global_model

        # 1. 尝试使用 NVIDIA NIM API
        nv_api_key = os.getenv("NVIDIA_API_KEY")
        if nv_api_key:
            try:
                print("✅ 使用 NVIDIA NIM 嵌入模型: nvidia/nv-embedqa-e5-v5")
                _global_model = NVIDIAEmbedder(nv_api_key)
                return _global_model
            except Exception as e:
                print(f"⚠️  连接 NVIDIA API 失败: {e}，正在回退到本地模型...")

        # 2. 尝试使用本地模型
        if SentenceTransformer is None:
            print("⚠️  sentence-transformers 未安装")
            return None

        try:
            if project_root is None:
                project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

            local_model_path = os.path.join(project_root, "rag_service", "models", "all-MiniLM-L6-v2")
            if os.path.exists(os.path.join(local_model_path, "config.json")):
                model_instance = SentenceTransformer(local_model_path)
                print(f"✅ 使用本地模型: {local_model_path}")
                _global_model = LocalEmbedder(model_instance)
                return _global_model

            print("--- 从HuggingFace在线加载模型'all-MiniLM-L6-v2' ---")
            model_instance = SentenceTransformer("all-MiniLM-L6-v2")
            _global_model = LocalEmbedder(model_instance)
            return _global_model
        except Exception as e:
            print(f"❌ 加载本地模型失败: {e}")
            return None

def get_model_dim(model: Optional[BaseEmbedder] = None, default_dim: int = 384) -> int:
    """获取模型的嵌入维度。"""
    if model is None:
        model = _global_model

    if model is None:
        return default_dim

    try:
        return model.get_dimension()
    except Exception:
        return default_dim



