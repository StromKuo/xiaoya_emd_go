# xiaoya_emd_go

> [!NOTE]
> 小雅元数据爬虫Golang版

# 功能列表

- Web UI 配置界面
- 预存 16 个爬虫服务器
- 默认自动同步路径为`每日更新` `纪录片（已刮削）`，12H 运行一次
- 网络限速和并发数配置
- DOH 配置，更好的 CF 网络连接

# Docker 运行

```shell
docker run -d \
    --name=xiaoya-emd-go \
    --restart=always \
    -p 127.0.0.1:8080:8080 \
    -v 媒体库目录:/media \
    ghcr.io/stromkuo/xiaoya-emd-go:sha-<commit>
```

# 工作流程

1. 启动加载配置,检查DNS解析是否正常.
2. 并发检查爬虫服务器,只读取最新数据时间,且响应最快3个服务器,1主2备.
3. 下载最新数据生成数据库,并生成本地媒体目录数据库.
4. 按照勾选的目录(如果没任何勾选,默认全部目录)进行时间戳对比误差10分钟内不处理,下载最新或缺少的文件,多余文件移动到回收站,防止误删.

# STRM 地址重写

STRM 重写默认关闭，不配置时保持原有同步行为。启用后，下载或更新 `.strm` 文件时只处理配置的来源主机中、路径以 `/d/` 开头的小雅 HTTP(S) 地址：入口地址替换为 `strmBaseUrl`，并从 `strmSignEndpoint` 获取当前 sign。sign 只在内存中缓存 10 分钟；签名接口短暂失败时，可在同一 token 和接口下使用最多 30 分钟的旧缓存。最近一次已完成全量应用的 sign 会持久化在配置中，但不会通过公开配置接口返回。

在 Web UI 的“配置 → STRM 地址重写”中填写：

- `STRM 基础地址`：Emby 和外部客户端可以访问的小雅地址，例如 `http://192.168.101.200:5678`。只能是 HTTP(S) URL，不能带查询参数或 fragment。
- `签名接口地址`：只读显示。默认 `http://xiaoya/api/getsignmd5`，由受信任的 `XIAOYA_STRM_SIGN_ENDPOINT` 启动环境变量或配置文件设置，Web UI/API 不能修改。元数据服务必须和小雅服务加入同一个 Docker 网络；路径必须为 `/api/getsignmd5`。管理 API 未配置鉴权时，建议只绑定 `127.0.0.1:8080`，不要让局域网直接访问管理端口。
- `小雅签名 token`：小雅登录 token。保存后只返回“已配置”状态，接口不会回显 token；需要更换时输入新 token，需要删除时勾选清除。
- `XIAOYA_STRM_TOKEN_FILE`：可选的受信任启动环境变量。设置后程序在每次刷新签名前重新读取该文件，且文件内容优先于 Web UI 中保存的 token；小雅镜像可使用当前 `/data/alist_auth_token.txt` 的内容，并建议以只读方式挂载。
- `允许来源主机`：每行一个小雅来源主机，例如 `xiaoya.host:5678`、`192.168.101.200:5678`。启用时至少填写一项，带端口精确匹配，不带端口匹配该主机的所有端口；已使用 `STRM 基础地址` 的目标主机也会自动允许，用于刷新已有签名。

签名接口使用固定的 `POST` 请求，`Content-Type` 为 `text/plain`，body 固定为 `cat md5`，并携带 `Authorization` token。body 不可通过 Web UI 或配置修改，因为该 CGI 入口具备命令执行能力。

保存配置后，新同步的 STRM 会自动改写。程序启动时及之后每 10 分钟检查签名；检测到签名变化后自动启动一次历史 STRM 全量修复。同一时刻只运行一个修复任务，修复完成后才持久化新的已应用签名；目录遍历或配置变化等全局失败会保留旧状态，单个解析异常会记录失败并允许其余文件完成，读取或写入失败会持久化相对路径并在后续检查中只重试这些文件。待重试路径最多保存 10,000 条，超过上限时会提示“失败过多，需要手工全量修复”，避免配置文件无限增长。重启后状态接口仍会显示待重试数量和溢出状态，但不会公开具体路径。旧文件也可点击“修复现有 STRM”，或调用以下接口查看后台进度：

```shell
curl -X POST http://127.0.0.1:8080/api/strm/rewrite-existing
curl http://127.0.0.1:8080/api/strm/rewrite-status
```

手工修复任务不会单独在容器启动时扫描；启动时的签名检查只会在已有签名状态缺失或发生变化时触发修复。修复不会处理 `recycle_bin`。下载或历史修复失败时，临时文件会被删除，原正式文件保留；历史修复使用同目录临时文件原子替换并保留 mtime。历史修复运行期间，STRM 下载会等待，避免旧内容覆盖新同步结果。

## Docker Compose 网络示例

参见 [`compose.strm.example.yml`](compose.strm.example.yml)。`xiaoya-emd-go` 和已有的 `xiaoya` 服务必须加入同一个网络，才能使用 `http://xiaoya/api/getsignmd5`；不需要 `privileged`、host 网络、Docker Socket 或宿主机 root 权限。示例将未鉴权管理端口绑定到 `127.0.0.1`；如需远程管理，应在外部增加鉴权和安全隧道。

```yaml
services:
  xiaoya-emd-go:
    image: ghcr.io/your-github-owner/xiaoya-emd-go:sha-<commit>
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - /your/media/path:/media
    networks:
      - xiaoya

networks:
  xiaoya:
    external: true
```

部署时请固定 commit SHA 或版本 tag，不建议长期使用浮动 `latest`。`/media/config.json` 会持久化 STRM 配置；回滚到旧镜像前可在 UI 中关闭 STRM 重写，已改写的 STRM 不会自动恢复原入口地址。

## 本地验证

```shell
gofmt -w main.go strm_rewrite.go strm_rewrite_test.go
go test ./...
go vet ./...
docker build -t xiaoya-emd-go:strm-test .
```

GitHub Actions 会在默认分支 push、`v*` tag 和手动触发时发布 GHCR 镜像，标签包含 `sha-<commit>`；版本 tag 还会生成对应的版本标签，不会自动覆盖 `latest`。
