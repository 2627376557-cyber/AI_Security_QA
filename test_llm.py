
import os
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI, APIStatusError, APIConnectionError

# 读取项目根目录的 .env
base_dir = Path(__file__).resolve().parent
load_dotenv(base_dir / ".env", override=True)

api_key = os.getenv("DEEPSEEK_API_KEY")
base_url = os.getenv(
    "DEEPSEEK_BASE_URL",
    "https://api.deepseek.com"
).strip().rstrip("/")

model = os.getenv(
    "DEEPSEEK_MODEL",
    "deepseek-flash"
).strip()

print("========== 配置检查 ==========")
print("API Key已读取：", bool(api_key))
print("Base URL：", base_url)
print("模型名称：", model)
print("预期接口：", base_url + "/chat/completions")
print("==============================")

if not api_key:
    raise RuntimeError("没有读取到API Key")

client = OpenAI(
    api_key=api_key,
    base_url=base_url,
    timeout=30.0,
    max_retries=0
)

try:
    print("\n正在请求DeepSeek API...")

    response = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "user",
                "content": "请用一句话解释CVE。"
            }
        ],
        max_tokens=100,
        stream=False
    )

    print("\n========== 调用成功 ==========")
    print(response.choices[0].message.content)

except APIStatusError as e:
    print("\n========== HTTP错误 ==========")
    print("HTTP状态码：", e.status_code)
    print("请求方法：", e.response.request.method)
    print("实际请求URL：", e.response.request.url)
    print("响应内容：", e.response.text[:500])

except APIConnectionError as e:
    print("\n========== 连接错误 ==========")
    print("错误类型：", type(e).__name__)
    print("错误信息：", str(e))

except Exception as e:
    print("\n========== 其他错误 ==========")
    print("错误类型：", type(e).__name__)
    print("错误信息：", str(e))
