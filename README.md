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
- 响应式界面、深色模式、卡片/紧凑视图

## 启动

```bash
git clone https://github.com/<your-account>/balance-sentinel.git
cd balance-sentinel
docker compose up -d --build
```

打开 http://localhost:3000 。默认管理员账号为 `admin` / `change-me-now`，首次启动前请务必通过环境变量修改：

```bash
ADMIN_USERNAME=your-admin ADMIN_PASSWORD=your-strong-password docker compose up -d --build
```

登录后点击“添加账号”。

可通过环境变量调整监控频率（秒）：

```bash
MONITOR_INTERVAL_SECONDS=60 docker compose up -d --build
```

默认只挂载 Docker named volume `balance_data`。生产环境建议在反向代理后使用 HTTPS，并限制管理台访问来源。

## 本地开发

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

前端静态文件位于 `public/`，生产镜像由 FastAPI 直接提供。

## API

- `GET/POST /api/accounts`
- `PATCH/DELETE /api/accounts/{id}`
- `POST /api/accounts/{id}/check`
- `POST /api/accounts/check-all`
- `GET /api/accounts/{id}/history?limit=30`
- `GET /api/health`
