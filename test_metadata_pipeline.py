
from qa.knowledge_base import SecurityKnowledgeBase


def main():
    kb = SecurityKnowledgeBase()

    target = "NVD:CVE-2026-85097"

    print("\n========== Chroma原始元数据 ==========")

    raw = kb.collection.get(
        ids=[target],
        include=["metadatas"]
    )

    assert raw["ids"], "目标记录不存在"

    metadata = raw["metadatas"][0]

    for key, value in metadata.items():
        print(f"{key}: {value}")

    print("\n========== 检索接口返回数据 ==========")

    results = kb.hybrid_search(
        "CVE-2026-85097是什么漏洞？"
    )

    assert results, "精确检索失败"

    for key, value in results[0].items():
        if key != "document":
            print(f"{key}: {value}")

    print("\n========== 字段传递检查 ==========")

    fields = [
        "source",
        "cvss",
        "cvss_severity",
        "risk_score",
        "risk_level"
    ]

    for field in fields:
        raw_value = metadata.get(field)
        retrieved_value = results[0].get(field)

        print(
            f"{field}: "
            f"Chroma={raw_value!r}, "
            f"检索结果={retrieved_value!r}"
        )

    print("\n元数据管线检查完成")


if __name__ == "__main__":
    main()
