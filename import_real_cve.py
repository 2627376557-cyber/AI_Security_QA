
import json
from pathlib import Path

from qa.service import update_knowledge_base

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "data" / "real_cve_samples.json"


def main():
    with DATA_FILE.open("r", encoding="utf-8") as f:
        records = json.load(f)

    if not isinstance(records, list):
        raise ValueError("数据文件必须是 JSON 数组")

    # 防止将演示用记录作为真实漏洞导入
    for record in records:
        if not record.get("cve_id", "").startswith("CVE-"):
            raise ValueError("发现无效的 CVE 编号")

        if "CVE-TEST-" in record["cve_id"]:
            raise ValueError("禁止导入虚构 CVE 测试记录")

        if "example.com" in record.get("source_url", ""):
            raise ValueError("禁止使用示例来源")

    print("准备导入的真实漏洞数量:", len(records))

    result = update_knowledge_base(records)

    print("入库结果：")
    print(json.dumps(result, ensure_ascii=False, indent=2))

    if result["failed"] != 0:
        raise RuntimeError("部分情报导入失败")

    print("真实 CVE 样本导入完成")


if __name__ == "__main__":
    main()
