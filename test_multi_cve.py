
from qa.service import ask_question
from qa.knowledge_base import SecurityKnowledgeBase


CVE_A = "CVE-2026-107717"
CVE_B = "CVE-2026-85097"


def main():
    print("=" * 60)
    print("多CVE检索与对比测试")
    print("=" * 60)

    kb = SecurityKnowledgeBase()

    question = (
        f"请比较{CVE_A}和{CVE_B}的"
        "漏洞类型、攻击前提、安全影响及修复建议。"
        "哪些信息目前缺乏证据？"
    )

    # 先验证两条记录能否同时检索到
    evidence = kb.hybrid_search(question, top_k=5)

    retrieved = {
        item.get("cve_id")
        for item in evidence
    }

    print("检索到的CVE：", retrieved)

    assert CVE_A in retrieved, f"缺少{CVE_A}"
    assert CVE_B in retrieved, f"缺少{CVE_B}"

    print("\n多CVE检索通过")

    # 再调用DeepSeek进行比较
    result = ask_question(question, history=[])
    assert result["answer"].strip(), (
        "DeepSeek返回空答案，多CVE问答测试失败"
    )

    print("\n========== 对比回答 ==========")
    print(result["answer"])

    assert isinstance(result["answer"], str), (
        "DeepSeek返回的答案类型不正确"
    )

    assert result["answer"].strip(), (
        "DeepSeek返回空答案，多CVE问答测试失败"
    )

    print("\n========== 引用来源 ==========")
    for source in result["sources"]:
        print(source)

    returned = {
        item.get("cve_id")
        for item in result["sources"]
    }

    assert CVE_A in returned
    assert CVE_B in returned

    print("\n========== 多CVE对比链路测试通过 ==========")


if __name__ == "__main__":
    main()
