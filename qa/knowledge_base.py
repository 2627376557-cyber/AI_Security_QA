
import json
from pathlib import Path
from typing import Any

import chromadb
from sentence_transformers import SentenceTransformer


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "data" / "chroma_db"

MODEL_NAME = (
    "sentence-transformers/"
    "paraphrase-multilingual-MiniLM-L12-v2"
)


class SecurityKnowledgeBase:
    """AI安全情报知识库：持久化、增量更新和语义检索。"""

    def __init__(self):
        DB_PATH.mkdir(parents=True, exist_ok=True)

        print("[KB] 正在初始化向量模型...")
        self.model = SentenceTransformer(
            MODEL_NAME,
            device="cpu"
        )

        self.client = chromadb.PersistentClient(
            path=str(DB_PATH)
        )

        self.collection = (
            self.client.get_or_create_collection(
                name="ai_security_intelligence",
                metadata={"hnsw:space": "cosine"}
            )
        )

        print("[KB] 初始化完成")
        print("[KB] 当前记录数:", self.count())

    def count(self) -> int:
        return self.collection.count()

    @staticmethod
    def validate_record(record: dict) -> None:
        if not isinstance(record, dict):
            raise ValueError("情报记录必须是字典")

        required = [
            "record_id",
            "title",
            "description"
        ]

        for field in required:
            value = record.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"缺少有效字段: {field}"
                )

        if not record["record_id"].strip():
            raise ValueError("record_id 不能为空")

    @staticmethod
    def build_document(record: dict) -> str:
        versions = record.get("affected_versions", [])

        if isinstance(versions, list):
            versions = ", ".join(map(str, versions))

        parts = [
            f"漏洞编号：{record.get('cve_id', '')}",
            f"标题：{record.get('title', '')}",
            f"产品：{record.get('product', '')}",
            f"漏洞描述：{record.get('description', '')}",
            f"漏洞类型：{record.get('vulnerability_type', '')}",
            f"受影响版本：{versions}",
            f"CVSS评分：{record.get('cvss_score', '')}",
            f"修复版本：{record.get('fix_version', '')}",
            f"修复建议：{record.get('remediation', '')}",
        ]

        return "\n".join(parts)


    def update_knowledge_base(
        self,
        records: list[dict]
    ) -> dict:
        """
        统一知识库更新接口。

        支持：
        1. A模块格式：id/document/metadata
        2. B模块格式：record_id/title/description
        """
        if not isinstance(records, list):
            raise TypeError("records 必须是列表")

        result = {
            "success": True,
            "inserted": 0,
            "updated": 0,
            "failed": 0,
            "errors": []
        }

        if not records:
            return result

        seen_ids = set()

        for record in records:
            try:
                if not isinstance(record, dict):
                    raise ValueError("情报记录必须是字典")

                # A模块原生格式
                if "id" in record and "document" in record:
                    record_id = record["id"]
                    document = record["document"]
                    metadata = record.get("metadata", {})

                    if not isinstance(metadata, dict):
                        raise ValueError("metadata 必须是字典")

                    metadata = dict(metadata)

                # B模块原有格式
                else:
                    self.validate_record(record)

                    record_id = record["record_id"]
                    document = self.build_document(record)

                    metadata = {
                        "cve_id": str(
                            record.get("cve_id") or ""
                        ),
                        "title": str(
                            record.get("title") or ""
                        ),
                        "product": str(
                            record.get("product") or ""
                        ),
                        "source": str(
                            record.get("source") or ""
                        ),
                        "source_url": str(
                            record.get("source_url") or ""
                        ),
                        "raw_json": json.dumps(
                            record,
                            ensure_ascii=False
                        )
                    }

                if not isinstance(record_id, str):
                    raise ValueError("记录ID必须是字符串")

                record_id = record_id.strip()

                if not record_id:
                    raise ValueError("记录ID不能为空")

                if not isinstance(document, str) or not document.strip():
                    raise ValueError("document不能为空")

                if record_id in seen_ids:
                    raise ValueError("本批次存在重复记录ID")

                seen_ids.add(record_id)

                # 统一B模块检索依赖的字段
                metadata["record_id"] = record_id

                if not metadata.get("title"):
                    metadata["title"] = document.strip()[:120]

                metadata["source_url"] = (
                    metadata.get("source_url")
                    or metadata.get("url")
                    or ""
                )

                # 清理Chroma不支持的元数据类型
                clean_metadata = {
                    key: value
                    for key, value in metadata.items()
                    if isinstance(key, str)
                    and isinstance(
                        value,
                        (str, int, float, bool)
                    )
                }

                # 判断新增还是更新
                existing = self.collection.get(
                    ids=[record_id],
                    include=[]
                )

                already_exists = bool(existing["ids"])

                # 与原有Chroma使用相同Embedding模型
                vector = self.model.encode(
                    document,
                    normalize_embeddings=True
                ).tolist()

                self.collection.upsert(
                    ids=[record_id],
                    documents=[document],
                    metadatas=[clean_metadata],
                    embeddings=[vector]
                )

                if already_exists:
                    result["updated"] += 1
                else:
                    result["inserted"] += 1

            except Exception as exc:
                result["failed"] += 1
                result["errors"].append({
                    "record_id": (
                        str(
                            record.get(
                                "id",
                                record.get("record_id", "unknown")
                            )
                        )
                        if isinstance(record, dict)
                        else "unknown"
                    ),
                    "error": str(exc)
                })

        result["success"] = result["failed"] == 0

        return result


    def search(
        self,
        question: str,
        top_k: int = 5
    ) -> list[dict[str, Any]]:
        if not isinstance(question, str) or not question.strip():
            return []

        total = self.count()
        if total == 0:
            return []

        top_k = max(1, min(top_k, total))

        query_vector = self.model.encode(
            question,
            normalize_embeddings=True
        ).tolist()

        result = self.collection.query(
            query_embeddings=[query_vector],
            n_results=top_k,
            include=[
                "documents",
                "metadatas",
                "distances"
            ]
        )

        output = []

        for record_id, document, meta, distance in zip(
            result["ids"][0],
            result["documents"][0],
            result["metadatas"][0],
            result["distances"][0]
        ):

            output.append({
                "record_id": record_id,
                "document": document,
                "cve_id": meta.get("cve_id", ""),
                "title": meta.get("title", ""),
                "source": meta.get("source", ""),
                "source_url": (
                    meta.get("source_url")
                    or meta.get("url")
                    or ""
                ),
                "published": meta.get("published", ""),
                "cwe": meta.get("cwe", ""),
                "cvss": meta.get("cvss"),
                "cvss_severity": meta.get(
                    "cvss_severity"
                ),
                "risk_score": meta.get("risk_score"),
                "risk_level": meta.get("risk_level", ""),
                "distance": float(distance)
            })


        def search_by_cve(self, cve_id: str) -> list[dict]:
            """
            根据 CVE 编号精确检索。
            不使用向量相似度。
            """
            import re

            if not isinstance(cve_id, str):
                return []

            cve_id = cve_id.strip().upper()

            if not re.fullmatch(
                    r"CVE-\d{4}-\d{4,}",
                    cve_id
            ):
                return []

            result = self.collection.get(
                where={"cve_id": cve_id},
                include=["documents", "metadatas"]
            )

            output = []

            for record_id, document, meta in zip(
                    result["ids"],
                    result["documents"],
                    result["metadatas"]
            ):
                output.append({
                    "record_id": record_id,
                    "document": document,
                    "cve_id": meta.get("cve_id", ""),
                    "title": meta.get("title", ""),
                    "source_url": meta.get("source_url", ""),
                    "distance": 0.0,
                    "source": meta.get("source", ""),
                    "published": meta.get("published", ""),
                    "cwe": meta.get("cwe", ""),
                    "cvss": meta.get("cvss"),
                    "cvss_severity": meta.get("cvss_severity"),
                    "risk_score": meta.get("risk_score"),
                    "risk_level": meta.get("risk_level", ""),

                })

            return output

        return output


    def search_by_cve(self, cve_id: str) -> list[dict]:
        """根据 CVE 编号执行精确检索。"""
        import re

        if not isinstance(cve_id, str):
            return []

        cve_id = cve_id.strip().upper()

        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
            return []

        result = self.collection.get(
            where={"cve_id": cve_id},
            include=["documents", "metadatas"]
        )

        output = []

        for record_id, document, meta in zip(
            result["ids"],
            result["documents"],
            result["metadatas"]
        ):

            output.append({
                "record_id": record_id,
                "document": document,
                "cve_id": meta.get("cve_id", ""),
                "title": meta.get("title", ""),
                "source": meta.get("source", ""),
                "source_url": (
                    meta.get("source_url")
                    or meta.get("url")
                    or ""
                ),
                "published": meta.get("published", ""),
                "cwe": meta.get("cwe", ""),
                "cvss": meta.get("cvss"),
                "cvss_severity": meta.get("cvss_severity"),
                "risk_score": meta.get("risk_score"),
                "risk_level": meta.get("risk_level", ""),
                "distance": 0.0
            })


        return output

    def hybrid_search(
        self,
        question: str,
        top_k: int = 5
    ) -> list[dict]:
        """CVE 精确检索优先，普通问题使用语义检索。"""
        import re

        if not isinstance(question, str) or not question.strip():
            return []

        top_k = max(1, top_k)

        cve_ids = re.findall(
            r"(?<![A-Za-z0-9])CVE-[0-9]{4}-[0-9]{4,}(?![0-9])",
            question,
            flags=re.IGNORECASE
        )

        if cve_ids:
            results = []
            seen = set()

            for cve_id in cve_ids:
                exact_results = self.search_by_cve(cve_id)

                for item in exact_results:
                    if item["record_id"] not in seen:
                        results.append(item)
                        seen.add(item["record_id"])

            return results[:top_k]

        return self.search(question, top_k=top_k)


if __name__ == "__main__":
    kb = SecurityKnowledgeBase()
    print("当前知识库记录数:", kb.count())
