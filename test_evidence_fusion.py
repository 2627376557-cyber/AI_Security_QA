
from qa.knowledge_base import SecurityKnowledgeBase
from qa.evidence_fusion import EvidenceFusion


def main():
    print("=" * 60)
    print("多文档证据融合 V1 测试")
    print("=" * 60)

    kb = SecurityKnowledgeBase()
    fusion = EvidenceFusion()

    question = (
        "比较CVE-2026-107717和"
        "CVE-2026-85097的安全风险"
    )

    evidences = kb.hybrid_search(
        question,
        top_k=5
    )

    print("\n原始检索数量：", len(evidences))

    assert evidences, "没有检索到证据"

    result = fusion.fuse(evidences)

    print("去重后证据数量：", result["evidence_count"])
    print("来源统计：", result["sources"])
    print("共同标识符关联数：", result["link_count"])

    print("\n========== 证据详情 ==========")

    for i, evidence in enumerate(
        result["evidences"],
        start=1
    ):
        print(f"\n证据{i}")
        print("记录ID：", evidence.get("record_id"))
        print("来源：", evidence.get("source"))
        print("CVE：", evidence["identifiers"]["cve_ids"])
        print("GHSA：", evidence["identifiers"]["ghsa_ids"])

    print("\n========== 关联详情 ==========")

    for link in result["links"]:
        print(
            link["identifier"],
            link["relation"],
            link["evidence_indices"]
        )

    print("\n========== 基础断言 ==========")

    # 去重结果不应超过原始检索结果
    assert result["evidence_count"] <= len(evidences)

    # 融合后的证据数量应与列表一致
    assert result["evidence_count"] == len(
        result["evidences"]
    )

    # 同一个record_id不应重复
    record_ids = [
        x["record_id"]
        for x in result["evidences"]
        if x.get("record_id")
    ]

    assert len(record_ids) == len(set(record_ids))

    # 关联必须包含至少两份证据
    for link in result["links"]:
        assert len(link["evidence_indices"]) >= 2
        assert link["verified"] is False

    print("所有基础断言通过")
    print("多文档证据融合V1测试完成")


if __name__ == "__main__":
    main()
