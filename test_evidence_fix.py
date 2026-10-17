
from qa.knowledge_base import SecurityKnowledgeBase
from qa.rag import SecurityRAG


def main():
    kb = SecurityKnowledgeBase()

    evidence = kb.hybrid_search(
        "CVE-2026-107717是什么漏洞？",
        top_k=3
    )

    assert len(evidence) >= 1

    context = SecurityRAG.format_evidence(evidence)

    print("\n========== 检索证据 ==========")
    print(context[:1500])

    assert (
        "关联CVE编号（知识库元数据）：CVE-2026-107717"
        in context
    )

    assert "GHSA-hmq2-7hp6-7crh" in context

    assert "CVSS严重性：" in context

    assert "团队综合风险等级：" in context

    print("\n========== RAG证据修复测试通过 ==========")


if __name__ == "__main__":
    main()
