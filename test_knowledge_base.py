
from qa.knowledge_base import SecurityKnowledgeBase


def main():
    kb = SecurityKnowledgeBase()

    # 以下均为虚构测试情报，不代表真实CVE
    records = [
        {
            "record_id": "demo-001",
            "cve_id": "CVE-TEST-0001",
            "title": "AI推理服务远程代码执行漏洞",
            "product": "Example Inference Server",
            "description": (
                "某AI推理服务存在输入验证缺陷，"
                "在特定条件下可能造成远程代码执行。"
            ),
            "vulnerability_type": "RCE",
            "affected_versions": ["1.0.0", "1.1.0"],
            "cvss_score": 9.1,
            "fix_version": "1.1.1",
            "remediation": "升级到修复版本。",
            "source_url": "https://example.com/rce"
        },
        {
            "record_id": "demo-002",
            "cve_id": "CVE-TEST-0002",
            "title": "大语言模型提示词注入风险",
            "product": "Example LLM Application",
            "description": (
                "攻击者通过恶意提示词影响模型行为，"
                "可能导致敏感信息泄露或越权调用工具。"
            ),
            "vulnerability_type": "Prompt Injection",
            "affected_versions": ["2.0.0"],
            "cvss_score": None,
            "fix_version": "",
            "remediation": "增加工具权限隔离和输入处理。",
            "source_url": "https://example.com/prompt"
        },
        {
            "record_id": "demo-003",
            "cve_id": "CVE-TEST-0003",
            "title": "模型服务接口身份认证漏洞",
            "product": "Example Model API",
            "description": (
                "模型服务的API鉴权不完善，"
                "可能导致未授权用户访问模型接口。"
            ),
            "vulnerability_type": "Authentication",
            "affected_versions": ["3.0.0"],
            "cvss_score": 7.5,
            "fix_version": "3.0.1",
            "remediation": "启用认证并升级服务。",
            "source_url": "https://example.com/auth"
        }
    ]

    print("\n========== 第一次入库 ==========")
    result1 = kb.update_knowledge_base(records)
    print(result1)

    assert result1["failed"] == 0

    count_before = kb.count()
    print("入库后记录数:", count_before)

    print("\n========== 重复入库测试 ==========")
    result2 = kb.update_knowledge_base(records)
    print(result2)

    count_after = kb.count()
    print("重复入库后记录数:", count_after)

    assert result2["failed"] == 0
    assert count_before == count_after

    print("\n========== 自然语言检索 ==========")

    question = "哪些AI服务漏洞可能造成远程代码执行？"
    print("用户问题:", question)

    results = kb.search(question, top_k=3)

    for index, item in enumerate(results, start=1):
        print(f"\n检索结果 {index}")
        print("编号:", item["cve_id"])
        print("标题:", item["title"])
        print("距离:", round(item["distance"], 4))
        print("来源:", item["source_url"])

    assert len(results) == 3
    assert results[0]["record_id"] == "demo-001", (
        "目标记录未排在第一位，需要进一步检查检索模型"
    )

    print("\n========== 测试通过 ==========")


if __name__ == "__main__":
    main()
