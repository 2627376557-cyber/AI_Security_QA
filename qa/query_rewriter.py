
import re


CVE_PATTERN = re.compile(
    r"CVE-[0-9]{4}-[0-9]{4,}",
    re.IGNORECASE
)


REFERENCE_WORDS = (
    "它",
    "这个漏洞",
    "该漏洞",
    "这个CVE",
    "上述漏洞",
    "前面那个",
    "如何修复",
    "影响哪些版本",
    "有什么危害",
    "怎么利用",
    "什么影响",
    "修复版本",
    "是否有补丁"
)


def rewrite_query(question: str, history=None) -> str:
    """
    根据历史消息补充被省略的CVE编号。

    仅处理明确的单CVE连续追问。
    不修改原始问题和history。
    """

    if not isinstance(question, str):
        raise TypeError("question必须是字符串")

    question = question.strip()
    history = history or []

    if not question:
        return question

    # 当前问题已经包含CVE，不需要改写
    if CVE_PATTERN.search(question):
        return question

    # 不是明显追问，不自动继承CVE
    if not any(word in question for word in REFERENCE_WORDS):
        return question

    # 从最近的历史用户消息中寻找CVE
    for message in reversed(history):

        if not isinstance(message, dict):
            continue

        if message.get("role") != "user":
            continue

        content = str(message.get("content") or "")

        cve_ids = list(dict.fromkeys(
            cve.upper()
            for cve in CVE_PATTERN.findall(content)
        ))

        if len(cve_ids) == 1:
            return f"{cve_ids[0]} {question}"

        # 最近用户消息涉及多个CVE时，不擅自选取
        if len(cve_ids) > 1:
            return question

    return question
