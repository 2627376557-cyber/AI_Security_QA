# AI Security QA — B 模块

## 项目简介

本项目是 AI 安全知识情报系统中的 RAG 智能问答模块，由 B 同学负责开发，供 C 同学的 LangGraph 总控系统调用。

目前支持：

- CVE 编号精确检索与自然语言语义检索
- 基于 DeepSeek 的安全情报问答
- 多轮对话问题改写
- 多文档证据整理和漏洞对比
- CVSS 严重性及团队综合风险信息展示
- 答案引用来源追踪

## 环境要求

- Python 3.11（当前开发环境）
- ChromaDB
- Sentence Transformers
- DeepSeek API

安装依赖：

```bash
pip install -r requirements.txt
```

复制 `.env.example` 为 `.env`，配置 `DEEPSEEK_API_KEY`。

## 核心接口

两个对外 Python 接口位于 `qa/service.py`。

### 1. 知识库更新

```python
from qa.service import update_knowledge_base

result = update_knowledge_base(records)
```

支持 A 模块的 `id/document/metadata` 格式，以及 B 模块原有的 `record_id/title/description` 格式。

返回结果包含 `success`、`inserted`、`updated`、`failed` 和 `errors`。

### 2. 智能问答

```python
from qa.service import ask_question

result = ask_question(
    question="CVE-2026-107717是什么漏洞？",
    history=[]
)

print(result["answer"])
print(result["sources"])
```

返回结果包含 `answer`、`sources` 和 `evidence_sufficient`。

注意：`evidence_sufficient=None` 表示尚未完成自动化证据充分性判定，不能解释为证据已得到验证。

## 数据存储

Chroma 集合名称：

`ai_security_intelligence`

Embedding 模型：

`sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2`

本地数据库目录：

`data/chroma_db/`

数据库文件不会上传至 GitHub。首次运行前需要通过知识库更新接口导入情报。

## 团队集成

- A 模块：安全情报采集、分析与导出
- B 模块：知识库存储、检索及 RAG 问答
- C 模块：FastAPI、LangGraph 总控与系统集成

C 模块通过 `qa.service` 调用 B 模块，不需要直接操作 Chroma 底层集合。

## 当前状态

核心检索、问答、证据整理和两个服务接口已通过基础测试。真实 A/B/C 联合集成、批量准确率评估及部署测试仍待完成。