# 贡献指南

感谢您对 AgentShield OS 的兴趣！我们欢迎各种形式的贡献。

## 行为准则

请阅读并遵守我们的 [行为准则](CODE_OF_CONDUCT.md)。我们希望构建一个友好、包容的社区。

## 如何贡献

### 报告 Bug

1. 搜索现有 [Issues](https://github.com/ZDY466/AgentShield/issues) 确保没有重复
2. 创建新 Issue，包含：
   - 清晰的标题
   - 详细的问题描述
   - 复现步骤
   - 期望行为和实际行为
   - 环境信息（Python 版本、操作系统等）

### 提出新功能

1. 搜索现有 [Discussions](https://github.com/ZDY466/AgentShield/discussions)
2. 在 Discussions 中描述您的想法
3. 获得共识后，创建 Feature Request Issue

### 提交代码

#### 开发环境设置

```bash
# 1. Fork 仓库
# 点击 GitHub 上的 Fork 按钮

# 2. 克隆仓库
git clone https://github.com/YOUR_USERNAME/AgentShield.git
cd AgentShield

# 3. 创建分支
git checkout -b feature/your-feature-name

# 4. 安装开发依赖
pip install -e ".[dev]"

# 5. 创建虚拟环境（推荐）
python -m venv venv
source venv/bin/activate  # Linux/macOS
# 或
venv\Scripts\activate  # Windows
```

#### 代码规范

- 遵循 [PEP 8](https://www.python.org/dev/peps/pep-0008/) 风格指南
- 使用类型注解
- 添加 docstring 文档
- 保持代码简洁

```python
def example_function(param: str) -> str:
    """
    函数简短描述。

    Args:
        param: 参数说明

    Returns:
        返回值说明

    Example:
        >>> example_function("test")
        'test'
    """
    return param
```

#### 提交 Pull Request

```bash
# 1. 确保所有测试通过
python -m pytest tests/

# 2. 提交您的更改
git add .
git commit -m "feat: 添加新功能"

# 3. 推送到您的分支
git push origin feature/your-feature-name

# 4. 在 GitHub 上创建 Pull Request
```

#### PR 描述模板

```markdown
## 描述
简要说明这个 PR 解决的问题

## 改动的类型
- [ ] Bug 修复
- [ ] 新功能
- [ ] 破坏性变更
- [ ] 文档更新

## 测试
- [ ] 我已添加测试覆盖这些更改
- [ ] 所有现有测试通过

## 检查清单
- [ ] 我的代码遵循项目的代码规范
- [ ] 我已经进行自我审查
- [ ] 我已经在本地测试了这些更改
```

### 改进文档

文档改进同样重要！您可以：

- 修正拼写和语法错误
- 添加示例
- 改进现有文档的清晰度
- 翻译文档到其他语言

### 赞助支持

如果您无法贡献代码，您可以通过以下方式支持：

- ⭐️ 给项目点赞
- 📢 分享给更多人
- 💼 申请使用或集成

## 开发流程

```
┌─────────────┐
│  Issue 创建  │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  分支创建    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  开发编码    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  本地测试    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  提交 PR     │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Code Review│
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  合并代码    │
└─────────────┘
```

## 常见问题

### 我如何开始？

从查看 [Good First Issues](https://github.com/ZDY466/AgentShield/labels/good%20first%20issue) 开始，这些是适合新手的任务。

### 我的 PR 会被接受吗？

我们欢迎所有高质量的贡献。您的 PR 将会经过审查，可能需要一些修改。如果有重大变更，建议先在 Discussions 中讨论。

### 我可以贡献哪些内容？

- 🐛 Bug 修复
- ✨ 新功能
- 📖 文档
- 🎨 代码优化
- 🧪 测试
- 🔧 构建/工具

## 联系方式

- GitHub: https://github.com/ZDY466/AgentShield
- 邮箱: 18335057001@163.com

---

感谢您的贡献！🎉
