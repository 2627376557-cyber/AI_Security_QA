
import json
from pathlib import Path

from qa.adapter import normalize_records


BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "data" / "a_export.json"


def main():
    with DATA_FILE.open("r", encoding="utf-8") as f:
        items = json.load(f)

    result = normalize_records(items)

    print("原始记录数：", len(items))
    print("转换成功：", result["converted"])
    print("转换失败：", result["failed"])

    if result["errors"]:
        print("错误示例：")
        for error in result["errors"][:5]:
            print(error)

    assert result["converted"] > 0

    for record in result["records"][:3]:
        print("\n记录ID：", record["record_id"])
        print("CVE编号：", record["cve_id"])
        print("标题：", record["title"])
        print("来源：", record["source"])
        print("CVSS：", record["cvss_score"])
        print("来源URL：", record["source_url"])

    print("\n适配器测试完成")


if __name__ == "__main__":
    main()
