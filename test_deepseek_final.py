
from qa.service import ask_question


def main():
    print("=" * 60)
    print("DeepSeek真实CVE问答测试")
    print("=" * 60)

    question = "CVE-2026-107717是什么漏洞？"

    result = ask_question(
        question=question,
        history=[]
    )

    print("\n========== AI回答 ==========")
    print(result["answer"])

    print("\n========== 引用来源 ==========")
    for source in result["sources"]:
        print(source)

    print("\n========== 测试完成 ==========")


if __name__ == "__main__":
    main()
