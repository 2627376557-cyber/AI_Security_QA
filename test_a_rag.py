
from qa.service import ask_question
from qa.knowledge_base import SecurityKnowledgeBase


def test_exact_search():
    print("\n========== 测试1：CVE精确检索 ==========")

    kb = SecurityKnowledgeBase()

    results = kb.hybrid_search(
        "CVE-2026-107717 是什么漏洞？"
    )

    assert len(results) >= 1, "未检索到目标CVE"

    for item in results:
        print("记录ID：", item["record_id"])
        print("CVE：", item["cve_id"])
        print("标题：", item["title"])
        print("来源：", item["source_url"])

    assert any(
        r["cve_id"] == "CVE-2026-107717"
        for r in results
    )

    print("CVE精确检索测试通过")


def test_real_rag():
    print("\n========== 测试2：真实情报问答 ==========")

    question = (
        "CVE-2026-107717 涉及什么安全问题？"
        "根据现有情报解释漏洞原理和安全影响，"
        "并提供来源。"
    )

    result = ask_question(
        question=question,
        history=[]
    )

    print("\n用户问题：", question)
    print("\nAI回答：")
    print(result["answer"])

    print("\n检索来源：")
    for source in result["sources"]:
        print(source)

    assert result["answer"].strip(), "回答为空"
    assert any(
        source["cve_id"] == "CVE-2026-107717"
        for source in result["sources"]
    ), "引用来源未包含目标CVE"

    print("\n基础RAG调用与来源关联测试通过")


def test_unknown_cve():
    print("\n========== 测试3：不存在的CVE ==========")

    question = "CVE-2099-999999 是什么漏洞？"

    result = ask_question(
        question=question,
        history=[]
    )

    print("回答：", result["answer"])
    print("来源：", result["sources"])

    assert result["sources"] == [], (
        "不存在的CVE不应返回其他漏洞来源"
    )

    print("不存在的CVE检索测试通过")


if __name__ == "__main__":
    test_exact_search()
    test_real_rag()
    test_unknown_cve()

    print("\n========== 自动化检查全部通过 ==========")
    print("注意：答案事实正确性仍需要人工核验。")
