# 贡献指南

感谢你对 pollux-go 的贡献意愿。本文档描述分支模型、提交流程与代码门禁。
开发前请先阅读 [架构与设计](docs/design/architecture.md) 了解项目定位与包职责。

## 分支模型

pollux-go 采用 **dev → main 的 squash-merge 工作流**：

| 分支 | 角色 | 历史 | 保护 |
|------|------|------|------|
| `dev` | **工作主线**，所有开发在此进行 | 保留完整细粒度历史（每个提交独立可追溯） | 无保护，可自由 push / force-push |
| `main` | **发布主干**，只接收稳定的压缩提交 | 线性，每个提交对应一次 dev→main 合并 | 受保护（见下） |

```
dev (工作主线，完整历史)
  │  攒一批有意义的变更后
  │  开 PR: dev → main
  │  CI 通过后 squash merge
  ▼
main (线性，每个提交 = 一个 PR)
```

### dev 分支

- 所有功能开发、修复、重构都在 `dev` 上进行。
- 保留全部提交历史，包括中间态、迭代修复、实验性提交——这是 dev 的设计目的。
- 无分支保护，维护者可自由 push 或 force-push（如压缩历史）。
- 提交信息应清晰描述改动，但不需要每个提交都完美（合并到 main 时会被压缩）。

### main 分支

- **只通过 PR squash-merge 接收变更**，不直接 push。
- 分支保护规则（GitHub 仓库设置）：
  - 强制 CI 通过（`Build & Test` + `Lint & Security` 两个 status check）
  - 强制线性历史（`required_linear_history`）
  - 禁止 force-push
  - `enforce_admins`：规则对管理员同样生效
- 每个提交的标题取 PR 标题，正文取 PR 描述。

## 提交流程

### 日常开发（在 dev 上）

```bash
git checkout dev
git pull                          # 同步最新
# ... 编码、测试 ...
git add -A
git commit -m "fix(smx509): 修复证书链验证遗漏中间证书"
git push origin dev
```

提交信息格式（Conventional Commits）：

```
<type>(<scope>): <description>
```

常用 type：`feat`（新功能）、`fix`（修复）、`docs`（文档）、`refactor`（重构）、
`test`（测试）、`chore`（工程）、`style`（格式）、`perf`（性能）、
`build`（构建/依赖）、`ci`（CI 配置）、`security`（安全修复）。

scope 用包名或模块名（如 `smx509`、`tls13gm`、`quicgm`、`tlcp`）。

### 合并到 main（按批次）

当 dev 上攒了一批有意义的变更（如一个功能集、一批安全修复、一次发版准备），
通过 PR squash-merge 合并到 main：

```bash
# 1. 确保 dev 已推送到 origin
git push origin dev

# 2. 创建 PR
gh pr create --base main --head dev \
  --title "fix(security): 本批安全修复摘要" \
  --body "变更清单..."

# 3. 等待 CI 通过（Build & Test + Lint & Security 两个 job）
gh pr checks <PR编号> --watch

# 4. squash merge
gh pr merge <PR编号> --squash
```

GitHub 会自动把 dev 相对 main 的增量压缩成 **1 个提交**，标题用 PR 标题，
正文用 PR 描述。main 保持线性。

### 发版（打 tag）

main 稳定后打 tag 触发自动 release：

```bash
git checkout main
git pull
git tag -a v0.X.Y -m "v0.X.Y: 简要说明"
git push origin v0.X.Y
```

push tag 会触发 `release.yml` workflow，GitHub 自动用 `--generate-notes`
从合并的 PR 创建 Release。

版本号遵循 [semver](https://semver.org/)：`v0.X.Y`（0.x 阶段，breaking change 走 minor）。

## 已知待办

### 移除 `http/` deprecation shim（计划下一个 minor 版本）

`http/` 目录是 `http`→`https` 重命名留下的兼容 shim，通过类型别名重新导出
`https` 的公共符号，使旧的 `github.com/iuboy/pollux-go/http` import 仍能编译
（staticcheck SA1019 标记为 deprecated）。

按弃用策略，shim 应至少在一个带 tag 的 minor 版本中发布过。该 shim 自 v0.1.1
起在全部 18 个已发布版本中持续存在，迁移窗口远超最低要求，可在下一个 minor
版本中安全移除。**移除步骤**：

1. 确认迁移窗口已过（`git log --oneline -- http/doc.go`，shim 已在所有历史 tag 中发布）。
2. 删除整个 `http/` 目录：`git rm -r http/`。
3. 搜索遗漏引用并迁移到 `https`：
   ```bash
   grep -rn 'pollux-go/http"' --include='*.go' .
   grep -rn 'polluxhttp\.\|polluxHttp\.' --include='*.go' .
   ```
4. 跑完整测试确认无残留依赖：`go build ./... && go test -count=1 ./...`。
5. release notes 公告破坏性变更：引导下游将 import 迁移到 `https`。

## 代码门禁

所有 PR 必须通过以下检查（定义在 `.github/workflows/ci.yml`）：

### Build & Test

```bash
go build ./...
go vet ./...
go test -race -tags=integration ./...
```

- `-race`：所有测试启用竞争检测。
- `-tags=integration`：包含集成测试（真实 socket、跨包流程）。需要 Tongsuo
  二进制的互通测试在 CI 上通过 `t.Skip` 跳过，本地可通过 `make test-integration` 运行。

### Lint & Security

```bash
# gofmt 漂移检查（排除 vendored quic-go/）
gofmt -l . | grep -v '^quic-go/'

# gosec 安全扫描（排除已审计规则，排除 quic-go/）
go list ./... | grep -v '/quic-go' | xargs gosec \
  -exclude G104,G115,G304,G401,G402,G405,G501,G502,G505 -quiet

# staticcheck 正确性检查（仅 SA，排除 SA1019，排除 quic-go/）
go list ./... | grep -v '/quic-go' | xargs staticcheck -checks 'SA*,-SA1019'
```

- **gosec 排除规则**的逐条理由见 [Makefile](Makefile) 头注释与
  [gosec 配置](docs/security/gosec-configuration.md)。
- **SA1019 排除**：SM2 是非 NIST 曲线，`crypto/ecdh` 不支持，只能用被弃用的
  `elliptic`/`ecdsa` API。
- **quic-go/ 排除**：vendored 的上游 fork（见 `quic-go/PATCHES.md`），
  其代码不在 pollux-go 的维护范围内。

### 本地预检

提交前建议本地跑一遍等价检查：

```bash
make fmt-check                              # gofmt 漂移
make vet                                    # go vet
make gosec                                  # 安全扫描
staticcheck -checks 'SA*,-SA1019' $(go list ./... | grep -v '/quic-go')
make test                                   # 完整测试（等价 CI）
```

或一步到位：

```bash
make fmt-check && make vet && make gosec && make test
```

## 本地开发

### 环境要求

- **Go 1.26+**（见 `go.mod`）
- 可选：[Tongsuo](https://github.com/Tongsuo-Project/Tongsuo) 二进制
  （用于 RFC 8998 互通测试，默认路径 `/opt/local/tongsuo`）

### 常用 make target

| Target | 用途 |
|--------|------|
| `make build` | 编译所有包 |
| `make test` | 全部测试（含集成，启用 race） |
| `make test-unit` | 仅单元测试 |
| `make test-integration` | 集成测试（需 Tongsuo） |
| `make cover-html` | HTML 覆盖率报告 |
| `make fmt` | 格式化所有源码 |
| `make fmt-check` | 检查格式漂移（CI 门禁） |
| `make vet` | go vet |
| `make gosec` | 安全扫描 |
| `make doc` | 本地预览包文档（pkgsite） |

### vendored quic-go

`quic-go/` 是 vendored 的上游 fork（Route C 的 GM QUIC 基础），通过 `go.mod`
的 `replace` 指令指向本地目录。其 `gm_*` 文件是 pollux-go 的 GM 补丁，其余为
上游代码。升级 quic-go 遵循 subtree 流程，详见 `quic-go/PATCHES.md`。

**不要**在 CI/lint 中修改 quic-go/ 的排除规则——上游代码不在本项目维护范围内。

## 安全相关贡献

涉及密码学、证书验证、握手协议的改动需特别谨慎：

- **修改任何 crypto 路径前**，评估影响范围（调用方、协议合规性）。
- **密钥材料清零**遵循 [内存与密钥管理](docs/security/memory-management.md) 的约定。
- **新增 unsafe 调用**需要充分理由（gosec G103 不排除，保持可见）。
- 安全修复的 PR 标题用 `fix(security): ...`，描述中说明威胁模型与修复原理。

## License

提交即表示你同意以 [MIT License](LICENSE) 发布你的贡献。
