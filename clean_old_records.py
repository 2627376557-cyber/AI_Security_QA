
from qa.knowledge_base import SecurityKnowledgeBase


OLD_IDS = [
    "demo-001",
    "demo-002",
    "demo-003",
    "CVE-2025-3248",
    "CVE-2024-34359",
    "CVE-2024-28224"
]


def main():
    kb = SecurityKnowledgeBase()

    print("清理前记录数：", kb.count())

    existing = kb.collection.get(
        ids=OLD_IDS,
        include=["metadatas"]
    )

    print("\n准备删除的记录：")
    for record_id in existing["ids"]:
        print("-", record_id)

    # 安全检查：不删除名单之外的记录
    assert set(existing["ids"]).issubset(set(OLD_IDS))

    if existing["ids"]:
        kb.collection.delete(ids=existing["ids"])

    print("\n清理后记录数：", kb.count())
    print("旧数据清理完成")


if __name__ == "__main__":
    main()
