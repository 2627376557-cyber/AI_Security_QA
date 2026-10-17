
import json
from pathlib import Path

from qa.knowledge_base import SecurityKnowledgeBase


ROOT = Path(__file__).resolve().parent
JSON_PATH = ROOT / "data" / "chroma_records.json"


def main():
    with JSON_PATH.open("r", encoding="utf-8") as f:
        records = json.load(f)

    expected_ids = {r["id"] for r in records}

    kb = SecurityKnowledgeBase()

    actual = kb.collection.get(include=[])
    actual_ids = set(actual["ids"])

    print("A模块记录数:", len(expected_ids))
    print("Chroma记录数:", len(actual_ids))

    missing = expected_ids - actual_ids
    extra = actual_ids - expected_ids

    print("缺失记录数:", len(missing))
    print("额外记录数:", len(extra))

    if missing:
        print("缺失示例:", list(missing)[:5])

    if extra:
        print("额外示例:", list(extra)[:5])

    assert not missing, "Chroma缺少A模块记录"
    assert not extra, "Chroma存在非A模块记录"

    print("\n========== 数据一致性测试通过 ==========")
    print("知识库全部记录均来自A模块导出的JSON")


if __name__ == "__main__":
    main()
