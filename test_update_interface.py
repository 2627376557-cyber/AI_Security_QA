
import chromadb
from sentence_transformers import SentenceTransformer

from qa.knowledge_base import (
    SecurityKnowledgeBase,
    MODEL_NAME
)


def create_test_kb():
    """
    创建完全独立的内存知识库。
    不调用SecurityKnowledgeBase.__init__，
    因此不会打开正式的data/chroma_db。
    """
    kb = SecurityKnowledgeBase.__new__(
        SecurityKnowledgeBase
    )

    kb.model = SentenceTransformer(
        MODEL_NAME,
        device="cpu"
    )

    kb.client = chromadb.EphemeralClient()

    kb.collection = kb.client.create_collection(
        name="test_update_interface_isolated",
        metadata={"hnsw:space": "cosine"}
    )

    return kb


def main():
    print("=" * 60)
    print("B模块知识库更新接口隔离测试")
    print("=" * 60)

    kb = create_test_kb()

    assert kb.count() == 0
    print("独立测试库创建成功")

    # 测试1：A模块格式
    a_record = {
        "id": "TEST:CVE-2099-0001",
        "document": "测试漏洞：某组件存在输入校验问题。",
        "metadata": {
            "source": "NVD",
            "cve_id": "CVE-2099-0001",
            "cvss": 9.8,
            "cvss_severity": "CRITICAL",
            "risk_score": 79.2,
            "risk_level": "HIGH",
            "url": "https://example.com/test-advisory"
        }
    }

    result_a = kb.update_knowledge_base([a_record])

    print("\n========== 测试1：A模块格式 ==========")
    print(result_a)

    assert result_a["success"] is True, result_a
    assert result_a["inserted"] == 1
    assert kb.count() == 1

    # 检查风险字段
    stored = kb.collection.get(
        ids=["TEST:CVE-2099-0001"],
        include=["metadatas", "documents"]
    )

    meta = stored["metadatas"][0]

    assert meta["cvss"] == 9.8
    assert meta["cvss_severity"] == "CRITICAL"
    assert meta["risk_score"] == 79.2
    assert meta["risk_level"] == "HIGH"
    assert meta["source"] == "NVD"
    assert (
        meta["source_url"]
        == "https://example.com/test-advisory"
    )

    assert (
        stored["documents"][0]
        == a_record["document"]
    )

    print("A模块格式写入成功，风险字段完整")

    # 测试2：B模块原有格式
    b_record = {
        "record_id": "TEST:CVE-2099-0002",
        "title": "测试漏洞B",
        "description": "某软件存在访问控制缺陷。",
        "cve_id": "CVE-2099-0002",
        "product": "TestProduct",
        "source_url": "https://example.com/test-b"
    }

    result_b = kb.update_knowledge_base([b_record])

    print("\n========== 测试2：B模块格式 ==========")
    print(result_b)

    assert result_b["success"] is True, result_b
    assert result_b["inserted"] == 1
    assert kb.count() == 2

    print("B模块原有格式写入成功")

    # 测试3：重复ID应该更新而不是新增
    a_updated = {
        **a_record,
        "document": "更新后的测试漏洞描述。",
        "metadata": {
            **a_record["metadata"],
            "risk_score": 85.0
        }
    }

    result_update = kb.update_knowledge_base(
        [a_updated]
    )

    print("\n========== 测试3：重复ID更新 ==========")
    print(result_update)

    assert result_update["success"] is True
    assert result_update["updated"] == 1
    assert result_update["inserted"] == 0
    assert kb.count() == 2

    updated = kb.collection.get(
        ids=["TEST:CVE-2099-0001"],
        include=["metadatas", "documents"]
    )

    assert (
        updated["metadatas"][0]["risk_score"]
        == 85.0
    )
    assert (
        updated["documents"][0]
        == "更新后的测试漏洞描述。"
    )

    print("重复ID更新成功，没有新增重复记录")

    # 测试4：非法记录应被拒绝
    bad_record = {
        "id": "",
        "document": "非法记录",
        "metadata": {}
    }

    result_bad = kb.update_knowledge_base(
        [bad_record]
    )

    print("\n========== 测试4：非法数据 ==========")
    print(result_bad)

    assert result_bad["success"] is False
    assert result_bad["failed"] == 1
    assert kb.count() == 2

    print("非法记录已拒绝，数据库数量未变化")

    # 测试5：空数据
    result_empty = kb.update_knowledge_base([])

    print("\n========== 测试5：空列表 ==========")
    print(result_empty)

    assert result_empty["success"] is True
    assert result_empty["inserted"] == 0
    assert result_empty["updated"] == 0
    assert kb.count() == 2

    print("空列表处理正常")

    print("\n" + "=" * 60)
    print("全部5项测试通过")
    print("最终测试库记录数：", kb.count())
    print("正式Chroma数据库未被打开或修改")
    print("=" * 60)


if __name__ == "__main__":
    main()
