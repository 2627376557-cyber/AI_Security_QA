
import json
from pathlib import Path

from qa.knowledge_base import SecurityKnowledgeBase

ROOT = Path(__file__).resolve().parent
JSON_PATH = ROOT / "data" / "chroma_records.json"


def main():
    # 1. 读取A同学数据
    with open(JSON_PATH, "r", encoding="utf-8") as f:
        records = json.load(f)

    print("读取记录数:", len(records))

    # 2. 加载你原有的Chroma和Embedding模型
    kb = SecurityKnowledgeBase()

    print("导入前记录数:", kb.count())

    # 3. 直接灌入，不进行格式适配
    batch_size = 16

    for start in range(0, len(records), batch_size):
        batch = records[start:start + batch_size]

        ids = [r["id"] for r in batch]
        documents = [r["document"] for r in batch]

        metadatas = []

        for r in batch:
            meta = dict(r["metadata"])

            # 补充B模块使用的字段
            meta["record_id"] = r["id"]
            meta["title"] = r["document"][:120]
            meta["source_url"] = meta.get("url") or ""
            metadatas.append(meta)

        # 保持Embedding模型一致
        embeddings = kb.model.encode(
            documents,
            batch_size=8,
            normalize_embeddings=True
        ).tolist()

        kb.collection.upsert(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
            embeddings=embeddings
        )

        print(
            f"已导入 {min(start + batch_size, len(records))}"
            f"/{len(records)}"
        )

    print("\n导入后记录数:", kb.count())
    print("A模块数据导入完成")


if __name__ == "__main__":
    main()
