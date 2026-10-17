
import re
from collections import defaultdict

from qa.knowledge_base import SecurityKnowledgeBase


CVE_PATTERN = re.compile(
    r"CVE-[0-9]{4}-[0-9]{4,}",
    re.IGNORECASE
)


def main():
    kb = SecurityKnowledgeBase()

    records = kb.collection.get(
        include=["documents", "metadatas"]
    )

    links = defaultdict(list)

    for record_id, document, meta in zip(
        records["ids"],
        records["documents"],
        records["metadatas"]
    ):
        source = meta.get("source", "")

        # 同时检查元数据和正文中的CVE编号
        cve_ids = set(
            match.upper()
            for match in CVE_PATTERN.findall(
                str(meta.get("cve_id", ""))
                + "\n"
                + document
            )
        )

        for cve_id in cve_ids:
            links[cve_id].append({
                "record_id": record_id,
                "source": source,
                "url": (
                    meta.get("source_url")
                    or meta.get("url")
                    or ""
                )
            })

    # 找出至少被两条记录提及的CVE
    shared = {
        cve_id: items
        for cve_id, items in links.items()
        if len({x["record_id"] for x in items}) >= 2
    }

    # 找出来自至少两个不同来源的关联
    cross_source = {
        cve_id: items
        for cve_id, items in shared.items()
        if len({x["source"] for x in items}) >= 2
    }

    print("\n========== 跨文档关联统计 ==========")
    print("知识库记录数：", len(records["ids"]))
    print("涉及CVE数量：", len(links))
    print("被多条记录提及的CVE：", len(shared))
    print("跨来源提及的CVE：", len(cross_source))

    print("\n========== 跨来源关联示例 ==========")

    for cve_id, items in list(cross_source.items())[:10]:
        print("\nCVE：", cve_id)

        for item in items:
            print(
                "来源：", item["source"],
                "| ID：", item["record_id"]
            )
            print("URL：", item["url"])

    print("\n跨来源关联统计完成")


if __name__ == "__main__":
    main()
