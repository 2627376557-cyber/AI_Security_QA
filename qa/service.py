
from functools import lru_cache

from qa.knowledge_base import SecurityKnowledgeBase
from qa.rag import SecurityRAG


@lru_cache(maxsize=1)
def get_knowledge_base():
    return SecurityKnowledgeBase()


@lru_cache(maxsize=1)
def get_rag():
    return SecurityRAG(
        knowledge_base=get_knowledge_base()
    )


def update_knowledge_base(records: list[dict]) -> dict:
    """
    接收情报监测模块的数据并更新知识库。
    供总控Agent调用。
    """
    kb = get_knowledge_base()
    return kb.update_knowledge_base(records)


def ask_question(
    question: str,
    history: list[dict] | None = None
) -> dict:
    """
    根据用户问题及历史消息生成回答。
    供总控Agent调用。
    """
    rag = get_rag()
    return rag.ask(
        question=question,
        history=history or [],
        top_k=3
    )
