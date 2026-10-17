
from qa.service import ask_question


def main():
    history = []

    questions = [
        "CVE-2026-107717是什么漏洞？",
        "它可能造成什么安全影响？",
        "这个漏洞有没有官方修复版本？"
    ]

    target_cve = "CVE-2026-107717"

    for index, question in enumerate(questions, start=1):
        print("\n" + "=" * 60)
        print(f"第{index}轮问答")
        print("=" * 60)

        result = ask_question(
            question=question,
            history=history
        )

        print("问题：", question)
        print("\n回答：")
        print(result["answer"])

        print("\n引用来源：")
        for source in result["sources"]:
            print(source)

        # 检查本轮是否仍然引用正确的CVE
        returned_cves = {
            source.get("cve_id")
            for source in result["sources"]
        }

        assert target_cve in returned_cves, (
            f"第{index}轮没有检索到目标CVE"
        )

        # 将本轮问答加入对话历史
        history.append({
            "role": "user",
            "content": question
        })

        history.append({
            "role": "assistant",
            "content": result["answer"]
        })

    print("\n" + "=" * 60)
    print("三轮RAG检索关联测试通过")
    print("=" * 60)


if __name__ == "__main__":
    main()
