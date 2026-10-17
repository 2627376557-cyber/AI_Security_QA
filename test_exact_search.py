
from qa.knowledge_base import SecurityKnowledgeBase


def main():
    kb = SecurityKnowledgeBase()

    print("\n========== 测试1：精确CVE查询 ==========")

    results = kb.hybrid_search(
        "CVE-2025-3248 的修复版本是什么？"
    )

    assert len(results) == 1
    assert results[0]["cve_id"] == "CVE-2025-3248"

    print("检索成功：", results[0]["title"])
    print("来源：", results[0]["source_url"])

    print("\n========== 测试2：不存在的CVE ==========")

    results = kb.hybrid_search(
        "CVE-2099-99999 的风险是什么？"
    )

    assert len(results) == 0
    print("不存在的CVE未返回错误记录")

    print("\n========== 测试3：多个CVE ==========")

    results = kb.hybrid_search(
        "比较 CVE-2025-3248 和 CVE-2024-34359"
    )

    cve_ids = {item["cve_id"] for item in results}

    assert cve_ids == {
        "CVE-2025-3248",
        "CVE-2024-34359"
    }

    print("多CVE检索成功：", cve_ids)

    print("\n========== 全部精确检索测试通过 ==========")


if __name__ == "__main__":
    main()
