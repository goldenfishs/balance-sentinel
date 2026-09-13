# Balance Sentinel

一个简洁的 Sub2API / New API 账号管理台，使用 FastAPI、SQLite 和原生前端构建，支持 Docker 一键部署。

## 功能

- Sub2API `/v1/usage`：自动识别钱包、订阅和 Key 限额模式
- New API `/api/user/self`：账户钱包余额
- New API `/api/usage/token/`：API Key 剩余额度
- 自动读取 New API `/api/status` 的 `quota_per_unit` 并换算展示金额
- 账号增删改、立即刷新、批量刷新、历史快照
- 后台定时监控、低余额提醒、正常/异常状态
- 凭证仅保存在服务端 SQLite 数据卷，列表接口自动脱敏
- 管理员登录、会话失效与工作区菜单
- 响应式界面、深色模式、卡片/紧凑视图

## Docker 部署

```bash
git clone https://github.com/goldenfishs/balance-sentinel.git
cd balance-sentinel
cp .env.example .env
docker compose up -d --build
```

打开 <http://localhost:3000>。首次访问会进入管理员设置页，请创建一个用户名和至少 12 个字符的密码；创建完成后才能进入账号管理台。公开部署时，先在本机或受控网络完成首次设置，再通过反向代理和 HTTPS 对外提供服务。

也可以在首次启动前通过环境变量创建管理员：

```bash
ADMIN_USERNAME=your-admin ADMIN_PASSWORD='use-a-password-with-12-or-more-chars' docker compose up -d --build
```

环境变量仅在数据库中还没有管理员时生效，项目没有预置账号或密码。管理员会话保存在 SQLite 中，有效期 24 小时，使用 HttpOnly、SameSite=Strict Cookie；HTTPS 请求会自动启用 Secure Cookie。若 TLS 由反向代理终止且应用只能看到 HTTP，请设置 `AUTH_COOKIE_SECURE=true`。

默认情况下 API 与前端使用同源访问，`CORS_ORIGINS` 为空。若单独部署前端，可填写逗号分隔的完整来源（例如 `https://panel.example.com,https://admin.example.com`）；通配符 `*` 不会启用宽泛跨域。

可通过环境变量调整监控频率（秒，最小 30）：

```bash
MONITOR_INTERVAL_SECONDS=60 docker compose up -d --build
```

默认只挂载 Docker named volume `balance_data`，余额数据和管理员信息都保存在其中。请为该卷配置备份与访问权限。

## 本地开发

项目需要 Python 3.12 或更新版本。使用仓库根目录启动，前端会由 FastAPI 在 3000 端口提供：

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
DATABASE_PATH=./data/balance-monitor.db uvicorn backend.main:app --reload --host 127.0.0.1 --port 3000
```

然后打开 <http://localhost:3000>，按首次访问设置管理员。也可以先导出 `ADMIN_USERNAME` 和 `ADMIN_PASSWORD` 进行一次性初始化。

## API

认证接口：

- `GET /api/auth/status`：检查是否需要首次设置或当前会话是否有效
- `POST /api/auth/setup`：首次创建唯一管理员并登录
- `POST /api/auth/login` / `POST /api/auth/logout`：登录与退出
- `GET /api/auth/me`：读取当前管理员

账号接口（均需管理员会话）：

- `GET/POST /api/accounts`
- `PATCH/DELETE /api/accounts/{id}`
- `POST /api/accounts/{id}/check`
- `POST /api/accounts/check-all`
- `GET /api/accounts/{id}/history?limit=30`

`GET /api/health` 为公开健康检查接口。
