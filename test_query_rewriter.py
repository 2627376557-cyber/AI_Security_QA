import inspect
import qa.query_rewriter as qr
from qa.query_rewriter import rewrite_query


def main():
    history = [
        {
            "role": "user",
            "content": "CVE-2026-107717是什么漏洞？"
        },
        {
            "role": "assistant",
            "content": "该漏洞涉及Banks聊天角色注入。"
        }
    ]

    cases = [
        (
            "它可能造成什么影响？",
            "CVE-2026-107717 它可能造成什么影响？"
        ),
        (
            "这个漏洞如何修复？",
            "CVE-2026-107717 这个漏洞如何修复？"
        ),
        (
            "CVE-2026-85097是什么漏洞？",
            "CVE-2026-85097是什么漏洞？"
        )
    ]

    for question, expected in cases:
        actual = rewrite_query(question, history)
        print("历史消息：", repr(history))
        print("原始问题：", repr(question))
        print("实际结果：", repr(actual))
        print("期望结果：", repr(expected))
        print("原始问题：", question)
        print("检索问题：", actual)

        assert actual == expected

    print("\n多轮问题改写测试通过")


if __name__ == "__main__":
    print("实际加载文件：", qr.__file__)
    print("函数定义：")
    print(inspect.getsource(qr.rewrite_query))

    print(
        "正则匹配：",
        qr.CVE_PATTERN.findall(
            "CVE-2026-107717是什么漏洞？"
        )
    )

    print(
        "追问词匹配：",
        any(
            word in "它可能造成什么影响？"
            for word in qr.REFERENCE_WORDS
        )
    )
    main()
