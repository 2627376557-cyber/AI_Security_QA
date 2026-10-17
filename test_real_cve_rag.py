
from qa.service import ask_question


questions = [
    "CVE-2025-3248 影响什么产品？修复版本是什么？",
    "CVE-2024-34359 的漏洞成因是什么？",
    "CVE-2024-28224 和 CVE-2025-3248 的风险有什么不同？"
]

for i, question in enumerate(questions, start=1):
    print(f"\n{'=' * 55}")
    print(f"问题 {i}: {question}")

    result = ask_question(question, history=[])

    print("\nAI 回答：")
    print(result["answer"])

    print("\n证据来源：")
    for source in result["sources"]:
        print(source["cve_id"], source["url"])
