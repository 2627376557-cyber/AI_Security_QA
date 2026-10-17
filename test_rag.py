
from qa.service import ask_question


def main():
    print("=" * 55)
    print("AI安全知识情报系统 - RAG问答测试")
    print("=" * 55)

    question = "哪些AI服务漏洞可能导致远程代码执行？"

    print("\n用户问题：")
    print(question)

    print("\n正在检索知识库并调用DeepSeek...")

    result = ask_question(
        question=question,
        history=[]
    )

    print("\n========== AI回答 ==========")
    print(result["answer"])

    print("\n========== 检索来源 ==========")

    for source in result["sources"]:
        print("证据编号：", source["evidence_id"])
        print("标题：", source["title"])
        print("记录ID：", source["record_id"])
        print("来源：", source["url"])
        print("-" * 40)

    print("\n========== 测试结束 ==========")


if __name__ == "__main__":
    main()
