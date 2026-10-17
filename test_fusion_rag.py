
from qa.rag import SecurityRAG


def main():
    print("=" * 60)
    print("多文档证据融合 + DeepSeek 集成测试")
    print("=" * 60)

    rag = SecurityRAG()

    question = (
        "比较CVE-2026-107717和"
        "CVE-2026-85097的攻击方式、"
        "影响范围和风险等级。"
        "请分别标注证据来源。"
    )

    result = rag.ask(
        question,
        history=[],
        top_k=5
    )

    print("\n========== DeepSeek回答 ==========")
    print(result["answer"])

    print("\n========== 引用来源 ==========")

    for source in result["sources"]:
        print(
            source["evidence_id"],
            "|",
            source["cve_id"],
            "|",
            source["record_id"]
        )
        print("URL：", source["url"])

    print("\n========== 自动检查 ==========")

    answer = result["answer"]

    assert answer.strip(), "DeepSeek回答为空"

    ids = {
        source["cve_id"]
        for source in result["sources"]
    }

    assert "CVE-2026-107717" in ids
    assert "CVE-2026-85097" in ids

    assert len(result["sources"]) == 2

    print("已检索到两个目标CVE")
    print("返回来源数量正确")
    print("DeepSeek返回非空答案")
    print("多文档RAG集成基础测试通过")


if __name__ == "__main__":
    main()
