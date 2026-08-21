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

STRM 重写默认关闭。启用后，程序会把符合条件的 `.strm` 地址改成播放器可以访问的小雅地址，并附加小雅当前签名。

例如，原始 STRM 内容是：

```text
http://xiaoya.host:5678/d/电影/示例.mp4
```

配置基础地址为 `https://xiaoya.example.com` 后，可能会改写成：

```text
https://xiaoya.example.com/d/电影/示例.mp4?sign=<当前签名>
```

程序只处理以下地址：

- URL 路径以 `/d/` 开头；
- URL 主机出现在“允许来源主机”中，或者已经是配置的目标主机；
- URL 使用 HTTP 或 HTTPS。

其他服务的 `/d/` 地址不会被改写。

## 推荐配置方式：只读挂载 token 文件

推荐让程序读取小雅当前的 token 文件，不要把 token 写进 Compose 或提交到 Git。小雅容器中的文件通常是：

```text
/data/alist_auth_token.txt
```

在 `xiaoya-emd-go` 服务中，将宿主机上的该文件只读挂载到容器，并设置环境变量：

```yaml
services:
  xiaoya-emd-go:
    environment:
      XIAOYA_STRM_SIGN_ENDPOINT: http://xiaoya/api/getsignmd5
      XIAOYA_STRM_TOKEN_FILE: /run/secrets/xiaoya_alist_token
    volumes:
      - /你的媒体目录:/media
      - /mnt/user/appdata/xiaoya/data/alist_auth_token.txt:/run/secrets/xiaoya_alist_token:ro
```

宿主机路径按实际安装位置修改。`xiaoya-emd-go` 和 `xiaoya` 必须加入同一个 Docker 网络，这样 `http://xiaoya/api/getsignmd5` 才能访问。签名接口地址必须是内部可信地址，不要把 token 发给公网地址。

程序每次刷新签名前都会重新读取 token 文件，因此小雅更新 token 后无需修改 Web UI。文件 token 的优先级高于 Web UI 中保存的 token。

## Web UI 中的填写方式

打开“配置 → STRM 地址重写”，按以下顺序填写：

1. 勾选“启用 STRM 重写”。
2. 填写 `STRM 基础地址`：Emby 和播放器实际能访问的小雅地址，例如 `https://xiaoya.example.com`。只能填写 HTTP(S) URL，不要带查询参数或 fragment。
3. 确认 `签名接口地址` 显示为 `http://xiaoya/api/getsignmd5`。这个字段只读，由 `XIAOYA_STRM_SIGN_ENDPOINT` 或配置文件设置，不能通过 Web UI 修改。
4. 如果已经挂载 token 文件，`小雅签名 token` 可以留空；页面显示“已配置”即可。如果没有挂载文件，则粘贴当前 `/data/alist_auth_token.txt` 的完整内容并保存。不要使用浏览器或其他应用中保存的旧 token。
5. 在 `允许来源主机` 中每行填写一个原始 STRM 实际使用的主机，例如：

   ```text
   xiaoya.host:5678
   {你的 NAS IP}:5678
   ```

   带端口时精确匹配；不带端口时匹配该主机的所有端口。至少填写一项。

“清除已保存 token”只删除 Web UI 写入配置文件的 token，不会删除或撤销小雅的 token 文件。使用只读 token 文件方案时，通常不需要勾选它；如果要删除旧的 Web UI 备用 token，可以勾选后保存。

签名请求始终是 `POST /api/getsignmd5`，请求体固定为 `cat md5`，并携带 `Authorization` header。请求体不能通过 Web UI 或配置修改，因为该 CGI 入口具备命令执行能力。

## 启用后的行为

保存配置后，新下载或更新的 STRM 会自动改写。程序启动时检查一次签名，之后每 10 分钟检查一次；检测到签名变化时，会自动修复历史 STRM。历史修复与正常 STRM 下载不会同时写入同一个文件。

也可以手工修复已有文件：

```shell
curl -X POST http://127.0.0.1:8080/api/strm/rewrite-existing
curl http://127.0.0.1:8080/api/strm/rewrite-status
```

修复任务不会处理 `recycle_bin`。读取或写入失败的文件会记录为待重试路径，后续检查时优先重试这些文件；待重试路径最多保存 10,000 条。超过上限时页面会显示“失败过多，需要手工全量修复”，此时需要点击“修复现有 STRM”。

空文件、多行内容、非法 URL 等解析失败不会自动重试。全量扫描完成后，程序会保存最多 10,000 条解析失败报告，报告包含相对路径和失败原因。页面会显示解析失败数量，并提供“下载解析失败报告”和“修复解析失败 STRM”按钮。也可以通过 API 获取和定向修复：

```shell
curl http://127.0.0.1:8080/api/strm/parse-failures
curl -X POST http://127.0.0.1:8080/api/strm/rewrite-parse-failures
```

定向修复只处理报告中的文件；文件修正后再次执行即可从报告中移除已成功处理的文件。报告超过 10,000 条时会标记为溢出，此时报告不完整，必须先执行一次“修复现有 STRM”全量扫描。解析失败报告和具体路径不会通过公开配置查询接口返回，但上述报告 API 会返回相对路径；管理 API 未配置鉴权，建议只绑定到 `127.0.0.1` 或通过安全隧道访问。

签名接口短暂失败时，程序会在同一接口和 token 下暂时使用最多 30 分钟的旧签名。历史修复只有在成功完成后才会记录新的已应用签名；旧正式 STRM 不会因为临时失败被删除。

## Docker Compose 网络示例

参见 [`compose.strm.example.yml`](compose.strm.example.yml)。`xiaoya-emd-go` 和已有的 `xiaoya` 服务必须加入同一个网络，才能使用 `http://xiaoya/api/getsignmd5`；不需要 `privileged`、host 网络、Docker Socket 或宿主机 root 权限。管理 API 默认没有鉴权，建议将管理端口绑定到 `127.0.0.1`；如需远程管理，应在外部增加鉴权和安全隧道。

```yaml
services:
  xiaoya-emd-go:
    image: ghcr.io/your-github-owner/xiaoya-emd-go:sha-<commit>
    ports:
      - "127.0.0.1:8080:8080"
    environment:
      XIAOYA_STRM_SIGN_ENDPOINT: http://xiaoya/api/getsignmd5
      XIAOYA_STRM_TOKEN_FILE: /run/secrets/xiaoya_alist_token
    volumes:
      - /your/media/path:/media
      - /mnt/user/appdata/xiaoya/data/alist_auth_token.txt:/run/secrets/xiaoya_alist_token:ro
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
