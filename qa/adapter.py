
import re
from typing import Any


CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def normalize_record(item: dict[str, Any]) -> dict:
    """将 A 同学的 Chroma 导出格式转换成现有 QA 格式。"""

    if not isinstance(item, dict):
        raise ValueError("情报记录必须是字典")

    metadata = item.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise ValueError("metadata 必须是字典")

    record_id = str(item.get("id") or "").strip()
    document = str(item.get("document") or "").strip()
    cve_id = str(metadata.get("cve_id") or "").strip().upper()

    if not record_id:
        raise ValueError("缺少 id")

    if not document:
        raise ValueError(f"{record_id}: document 为空")

    if cve_id and not CVE_PATTERN.fullmatch(cve_id):
        raise ValueError(f"{record_id}: CVE 编号格式无效")

    # 删除完全重复的段落，保留原来的段落顺序。
    paragraphs = re.split(r"\n\s*\n", document)
    cleaned = []
    seen = set()

    for paragraph in paragraphs:
        paragraph = paragraph.strip()
        if not paragraph:
            continue

        key = " ".join(paragraph.split())
        if key not in seen:
            cleaned.append(paragraph)
            seen.add(key)

    description = "\n\n".join(cleaned)

    # 缺少标题时优先取正文首句，不使用虚构标题。
    title = str(item.get("title") or "").strip()
    if not title:
        first_line = description.splitlines()[0]
        title = first_line[:150]

    cvss = metadata.get("cvss")
    if cvss in ("", None):
        cvss = None
    else:
        cvss = float(cvss)
        if not 0 <= cvss <= 10:
            raise ValueError(f"{record_id}: CVSS 超出范围")

    source_url = str(metadata.get("url") or "").strip()

    # 保留原始元数据中的所有富化字段
    record = {
        "record_id": record_id,
        "cve_id": cve_id,
        "title": title,
        "description": description,
        "product": str(
            metadata.get("product") or ""
        ),
        "affected_versions": (
            metadata.get("affected_versions") or []
        ),
        "cvss_score": cvss,
        "fix_version": str(
            metadata.get("fix_version") or ""
        ),
        "remediation": str(
            metadata.get("remediation") or ""
        ),
        "source_url": source_url,
        "source": str(metadata.get("source") or ""),
        "published": str(metadata.get("published") or ""),
        "cwe": metadata.get("cwe"),
        "pocs": metadata.get("pocs"),
        "assets": metadata.get("assets"),
        "attack_chain": metadata.get("attack_chain"),
        "risk_score": metadata.get("risk_score"),
        "risk_level": metadata.get("risk_level"),
        "raw_metadata": metadata
    }

    return record


def normalize_records(items: list[dict]) -> dict:
    """批量转换；单条错误不影响其他记录。"""

    if not isinstance(items, list):
        raise TypeError("输入必须是 list[dict]")

    records = []
    errors = []

    for index, item in enumerate(items):
        try:
            records.append(normalize_record(item))
        except Exception as exc:
            errors.append({
                "index": index,
                "error": str(exc)
            })

    return {
        "records": records,
        "converted": len(records),
        "failed": len(errors),
        "errors": errors
    }
