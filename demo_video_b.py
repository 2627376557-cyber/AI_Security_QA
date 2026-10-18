
from qa.service import ask_question


def main():
    print("=" * 60)
    print("AI 安全知识情报系统 —— B 模块 RAG 问答演示")
    print("=" * 60)

    print("\n请输入你的安全问题，例如：")
    print("CVE-2026-85097 是什么漏洞？它的风险等级和修复情况如何？")

    question = input("\n【用户提问】> ").strip()

    if not question:
        print("问题不能为空，请重新运行程序。")
        return

    print("\n【用户问题】")
    print(question)

    print("\n【系统处理】")
    print("正在调用 B 模块问答接口……")
    print("系统将执行知识库检索，并调用大模型生成回答。")

    try:
        result = ask_question(question)

        print("\n" + "=" * 60)
        print("【模型回答】")
        print("=" * 60)
        print(result.get("answer", "未返回回答"))

        print("\n" + "=" * 60)
        print("【参考来源】")
        print("=" * 60)

        sources = result.get("sources", [])

        if not sources:
            print("本次回答没有返回参考来源。")
        else:
            for source in sources:
                print(f"证据编号：{source.get('evidence_id', '未提供')}")
                print(f"漏洞编号：{source.get('cve_id', '未提供')}")
                print(f"记录 ID：{source.get('record_id', '未提供')}")
                print(f"标题：{str(source.get('title', '未提供'))[:200]}")
                print(f"来源链接：{source.get('url', '未提供')}")
                print("-" * 50)

        print("\n【本次演示结束】")

    except Exception as exc:
        print(f"\n【运行失败】{type(exc).__name__}: {exc}")
        raise


if __name__ == "__main__":
    main()
