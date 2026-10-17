
import os
import sys
from pathlib import Path

A_ROOT = Path(r"E:\intel-monitor")
A_DB = A_ROOT / "data" / "intel.db"

# 临时兼容A模块的顶层collectors导入
if str(A_ROOT) not in sys.path:
    sys.path.append(str(A_ROOT))

# 显式使用A模块自己的数据库
os.environ["INTEL_DB_PATH"] = str(A_DB)

from app.monitor.service import export_for_chroma


def main():
    records = export_for_chroma()

    print("导出记录数：", len(records))

    if not records:
        raise RuntimeError("A模块返回空数据")

    print("第一条ID：", records[0]["id"])
    print(
        "CVSS严重性：",
        records[0]["metadata"].get(
            "cvss_severity", "字段不存在"
        )
    )

    print("\nA/B跨项目调用成功")


if __name__ == "__main__":
    main()
