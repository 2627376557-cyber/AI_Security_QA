
from qa.knowledge_base import SecurityKnowledgeBase
from qa.evidence_fusion import EvidenceFusion
from qa.rag import SecurityRAG


def main():
    print("=" * 60)
    print("多文档融合证据上下文测试")
    print("=" * 60)

    kb = SecurityKnowledgeBase()
    fusion = EvidenceFusion()

    question = (
        "比较CVE-2026-107717和"
        "CVE-2026-85097的攻击方式与风险"
    )

    evidences = kb.hybrid_search(question, top_k=5)

    result = fusion.fuse(evidences)

    # 继续使用原有RAG证据格式，
    # 保证不破坏已验证的CVSS和来源字段
    context = SecurityRAG.format_evidence(
        result["evidences"]
    )

    print("\n========== 融合后的证据 ==========")
    print(context)

    assert result["evidence_count"] == 2

    assert "CVE-2026-107717" in context
    assert "CVE-2026-85097" in context

    assert "GitHub Advisories" in context
    assert "NVD" in context

    assert "CVSS严重性：CRITICAL" in context
    assert "团队综合风险等级：HIGH" in context

    # 两个不同漏洞不应存在共同标识符关联
    assert result["link_count"] == 0

    print("\n========== 测试结果 ==========")
    print("两份证据均已进入RAG上下文")
    print("不同漏洞未被错误关联")
    print("来源与风险字段保留完整")
    print("融合证据上下文测试通过")


if __name__ == "__main__":
    main()
