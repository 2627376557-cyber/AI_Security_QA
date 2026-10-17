
import os
import sys
from pathlib import Path

from qa.knowledge_base import SecurityKnowledgeBase


# A同学的项目路径
A_ROOT = Path(r"E:\intel-monitor")

# A同学的SQLite数据库
A_DB = A_ROOT / "data" / "intel.db"

# 兼容A模块当前的顶层collectors导入
if str(A_ROOT) not in sys.path:
    sys.path.append(str(A_ROOT))

# 明确指定数据库路径
os.environ["INTEL_DB_PATH"] = str(A_DB)

from app.monitor.service import export_for_chroma


BATCH_SIZE = 16


def main():
    print("=" * 60)
    print("A模块 → B模块 Chroma同步")
    print("=" * 60)

    if not A_DB.is_file():
        raise FileNotFoundError(
            f"找不到A模块数据库：{A_DB}"
        )

    # 1. 从A模块直接导出数据
    records = export_for_chroma()

    print("A模块导出数量：", len(records))

    if not records:
        raise RuntimeError("A模块没有返回情报")

    # 2. 校验数据
    ids = [r["id"] for r in records]

    if len(ids) != len(set(ids)):
        raise RuntimeError("A模块返回了重复ID")

    severity_count = sum(
        "cvss_severity" in r.get("metadata", {})
        for r in records
    )

    print(
        "包含cvss_severity字段：",
        severity_count
    )

    if severity_count != len(records):
        raise RuntimeError(
            "部分记录缺少cvss_severity，停止同步"
        )

    # 3. 打开B模块原有知识库
    kb = SecurityKnowledgeBase()

    print("同步前记录数：", kb.count())

    # 4. 分批更新Chroma
    for start in range(0, len(records), BATCH_SIZE):
        batch = records[start:start + BATCH_SIZE]

        batch_ids = [r["id"] for r in batch]
        documents = [r["document"] for r in batch]

        metadatas = []

        for r in batch:
            meta = dict(r["metadata"])

            # 补充B模块检索需要的字段
            meta["record_id"] = r["id"]
            meta["title"] = r["document"].strip()[:120]
            meta["source_url"] = meta.get("url") or ""

            # Chroma只接受基础类型元数据
            clean_meta = {}

            for key, value in meta.items():
                if isinstance(
                    value,
                    (str, int, float, bool)
                ):
                    clean_meta[key] = value

            metadatas.append(clean_meta)

        # 统一使用B模块已有的Embedding模型
        embeddings = kb.model.encode(
            documents,
            batch_size=8,
            normalize_embeddings=True,
            show_progress_bar=False
        ).tolist()

        kb.collection.upsert(
            ids=batch_ids,
            documents=documents,
            metadatas=metadatas,
            embeddings=embeddings
        )

        print(
            "同步进度：",
            min(start + BATCH_SIZE, len(records)),
            "/",
            len(records)
        )

    # 5. 验证同步结果
    actual_ids = set(
        kb.collection.get(include=[])["ids"]
    )

    expected_ids = set(ids)

    print("\n========== 同步结果 ==========")
    print("A模块记录数：", len(expected_ids))
    print("Chroma记录数：", len(actual_ids))

    missing = expected_ids - actual_ids
    extra = actual_ids - expected_ids

    print("缺失记录数：", len(missing))
    print("额外记录数：", len(extra))

    assert not missing, "Chroma缺少A模块记录"
    assert not extra, "Chroma存在非A模块记录"

    # 6. 验证CVSS严重性字段
    target = kb.collection.get(
        ids=["NVD:CVE-2026-85097"],
        include=["metadatas"]
    )

    if target["ids"]:
        meta = target["metadatas"][0]

        print("\n========== 风险字段验证 ==========")
        print("CVE：", meta.get("cve_id"))
        print("CVSS：", meta.get("cvss"))
        print(
            "CVSS严重性：",
            meta.get("cvss_severity")
        )
        print(
            "团队综合风险分：",
            meta.get("risk_score")
        )
        print(
            "团队综合风险等级：",
            meta.get("risk_level")
        )

    print("\nA/B模块同步完成")


if __name__ == "__main__":
    main()
