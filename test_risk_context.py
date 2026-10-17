
from qa.knowledge_base import SecurityKnowledgeBase
from qa.rag import SecurityRAG


def main():
    print("=" * 60)
    print("RAG风险字段传递测试")
    print("=" * 60)

    kb = SecurityKnowledgeBase()

    # 查询A同学提供的真实情报
    evidence = kb.hybrid_search(
        "CVE-2026-85097是什么漏洞？",
        top_k=3
    )

    assert evidence, "未检索到目标漏洞"

    # 确保检索的是指定CVE
    assert evidence[0]["cve_id"] == "CVE-2026-85097"

    # 构建DeepSeek实际使用的证据上下文
    context = SecurityRAG.format_evidence(evidence)

    print("\n========== RAG证据内容 ==========")
    print(context[:1500])

    # 检查CVSS官方严重性
    assert "CVSS基础分：9.8" in context
    assert "CVSS严重性：CRITICAL" in context

    # 检查团队综合风险
    assert "团队综合风险分：79.2" in context
    assert "团队综合风险等级：HIGH" in context

    # 检查CVE编号和来源
    assert "CVE-2026-85097" in context
    assert "https://bricksforge.io/version-changelog/" in context

    print("\n========== 测试通过 ==========")
    print("CVSS官方严重性与团队综合风险字段已正确进入RAG")


if __name__ == "__main__":
    main()
