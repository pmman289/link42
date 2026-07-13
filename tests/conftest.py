from __future__ import annotations

import os


# 测试使用固定的独立主密钥，避免在宿主机配置目录生成运行时密钥文件。
os.environ.setdefault("LINK42_MASTER_KEY", "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=")
