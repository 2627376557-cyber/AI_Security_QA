
from qa.service import ask_question


def main():
    print("=" * 60)
    print("B模块对外问答接口测试")
    print("=" * 60)

    question = (
        "CVE-2026-107717是什么漏洞？"
        "请说明攻击原理和影响，并标注证据。"
    )

    result = ask_question(
        question=question,
        history=[]
    )

    print("\n========== 接口返回结果 ==========")
    print("回答：")
    print(result.get("answer", ""))

    print("\n来源：")
    for source in result.get("sources", []):
        print(source)

    print("\n证据充分性：")
    print(result.get("evidence_sufficient"))

    assert isinstance(result, dict)
    assert isinstance(result.get("answer"), str)
    assert result["answer"].strip()
    assert isinstance(result.get("sources"), list)

    print("\nB模块问答接口测试通过")


if __name__ == "__main__":
    main()
