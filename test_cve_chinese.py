
from qa.knowledge_base import SecurityKnowledgeBase


TARGET = "CVE-2026-107717"


def main():
    kb = SecurityKnowledgeBase()

    questions = [
        "CVE-2026-107717是什么漏洞？",
        "CVE-2026-107717 是什么漏洞？",
        "请分析CVE-2026-107717的影响",
        "cve-2026-107717如何修复？",
        "CVE-2026-107717 它可能造成什么影响？"
    ]

    for index, question in enumerate(questions, 1):
        print(f"\n========== 测试{index} ==========")
        print("问题：", question)

        results = kb.hybrid_search(
            question,
            top_k=3
        )

        returned_cves = [
            item.get("cve_id")
            for item in results
        ]

        print("检索到的CVE：", returned_cves)

        assert TARGET in returned_cves, (
            f"测试{index}失败：未找到目标CVE"
        )

        for item in results:
            assert item.get("cve_id") == TARGET, (
                "精确查询混入了其他CVE"
            )

        print("测试通过")

    print("\n" + "=" * 60)
    print("中文CVE精确检索全部通过")
    print("=" * 60)


if __name__ == "__main__":
    main()
