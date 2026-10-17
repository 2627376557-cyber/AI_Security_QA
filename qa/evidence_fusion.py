
import re
from collections import defaultdict


CVE_PATTERN = re.compile(
    r"CVE-[0-9]{4}-[0-9]{4,}",
    re.IGNORECASE
)

GHSA_PATTERN = re.compile(
    r"GHSA-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}",
    re.IGNORECASE
)


class EvidenceFusion:
    """
    多文档证据融合 V1

    功能：
    1. 根据record_id去重
    2. 提取CVE、GHSA标识符
    3. 判断是否存在明确的漏洞编号关联
    4. 统计证据来源
    5. 生成可供RAG使用的融合结果

    注意：
    不根据主题相似性直接认定两个漏洞相同。
    """

    @staticmethod
    def extract_identifiers(evidence):
        text = "\n".join([
            str(evidence.get("record_id") or ""),
            str(evidence.get("cve_id") or ""),
            str(evidence.get("document") or "")
        ])

        return {
            "cve_ids": sorted({
                x.upper()
                for x in CVE_PATTERN.findall(text)
            }),
            "ghsa_ids": sorted({
                x.upper()
                for x in GHSA_PATTERN.findall(text)
            })
        }

    @staticmethod
    def deduplicate(evidences):
        result = []
        seen = set()

        for evidence in evidences:
            record_id = evidence.get("record_id")

            if record_id:
                key = ("id", str(record_id))
            else:
                key = (
                    "content",
                    str(evidence.get("source") or ""),
                    str(evidence.get("document") or "")
                )

            if key in seen:
                continue

            seen.add(key)
            result.append(evidence)

        return result

    def fuse(self, evidences):
        evidences = self.deduplicate(evidences)

        identifier_index = defaultdict(set)
        sources = defaultdict(int)
        enriched = []

        for index, evidence in enumerate(evidences):
            identifiers = self.extract_identifiers(evidence)

            item = dict(evidence)
            item["identifiers"] = identifiers
            enriched.append(item)

            source = str(evidence.get("source") or "UNKNOWN")
            sources[source] += 1

            for identifier in (
                identifiers["cve_ids"]
                + identifiers["ghsa_ids"]
            ):
                identifier_index[identifier].add(index)

        # 共同出现相同标识符，是候选关联，
        # 不是多个来源已经相互证实漏洞的证明。
        shared_identifiers = {
            identifier: sorted(indices)
            for identifier, indices in identifier_index.items()
            if len(indices) >= 2
        }

        links = []

        for identifier, indices in shared_identifiers.items():
            links.append({
                "identifier": identifier,
                "type": (
                    "CVE"
                    if identifier.startswith("CVE-")
                    else "GHSA"
                ),
                "evidence_indices": indices,
                "relation": "共同提及相同标识符",
                "verified": False
            })

        return {
            "evidences": enriched,
            "evidence_count": len(enriched),
            "sources": dict(sources),
            "links": links,
            "link_count": len(links),
            "has_shared_identifier": bool(links)
        }
