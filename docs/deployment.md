# AgentShield OS 部署指南

## 部署模式

AgentShield OS 支持三种部署模式：

| 模式 | 适用场景 | 复杂度 |
|------|----------|--------|
| SaaS | 快速上线、云端管理 | 低 |
| VPC | 企业云环境 | 中 |
| 本地 | 金融、政府、离线 | 高 |

---

## 本地部署

### 环境要求

| 组件 | 要求 |
|------|------|
| Python | 3.9+ |
| 内存 | 4GB+ |
| 磁盘 | 10GB+ |
| OS | Linux/macOS/Windows |

### 安装步骤

```bash
# 1. 克隆项目
git clone https://github.com/your-repo/agentshield.git
cd agentshield

# 2. 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/macOS
# 或
venv\Scripts\activate  # Windows

# 3. 安装依赖
pip install -e .

# 4. 配置
cp config.example.yaml config.yaml
# 编辑 config.yaml

# 5. 运行
python -m agentshield
```

---

## Docker 部署

### Dockerfile

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY . .
RUN pip install -e .

EXPOSE 8000

CMD ["python", "-m", "agentshield", "--host", "0.0.0.0", "--port", "8000"]
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  agentshield:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./config.yaml:/app/config.yaml
      - ./data:/app/data
    environment:
      - LOG_LEVEL=INFO
      - DATABASE_URL=postgresql://user:pass@db:5432/agentshield
    depends_on:
      - db
      - redis

  db:
    image: postgres:14
    environment:
      POSTGRES_USER: agentshield
      POSTGRES_PASSWORD: secure_password
      POSTGRES_DB: agentshield
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine

volumes:
  pgdata:
```

### 启动

```bash
docker-compose up -d
```

---

## Kubernetes 部署

### deployment.yaml

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agentshield
spec:
  replicas: 3
  selector:
    matchLabels:
      app: agentshield
  template:
    metadata:
      labels:
        app: agentshield
    spec:
      containers:
      - name: agentshield
        image: agentshield:latest
        ports:
        - containerPort: 8000
        env:
        - name: LOG_LEVEL
          value: "INFO"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: agentshield-secrets
              key: database-url
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: agentshield
spec:
  selector:
    app: agentshield
  ports:
  - port: 80
    targetPort: 8000
  type: ClusterIP
```

### 部署

```bash
kubectl apply -f deployment.yaml
```

---

## 配置说明

### 配置文件结构

```yaml
# config.yaml
agentshield:
  # 安全层配置
  security:
    enabled: true
    level: high
    
  # 防火墙配置
  firewall:
    enabled: true
    sensitive_data:
      block_critical: true
      block_high: true
      
  # 审计配置
  audit:
    enabled: true
    storage: database  # database, file, elasticsearch
    retention_days: 90
    
  # 监控配置
  monitoring:
    enabled: true
    metrics_port: 9090
    
  # 日志
  logging:
    level: INFO
    format: json
```

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `AGENTSHIELD_LOG_LEVEL` | 日志级别 | INFO |
| `AGENTSHIELD_CONFIG_PATH` | 配置文件路径 | ./config.yaml |
| `AGENTSHIELD_DATABASE_URL` | 数据库连接 | - |
| `AGENTSHIELD_REDIS_URL` | Redis 连接 | - |
| `AGENTSHIELD_SECRET_KEY` | 密钥 | 自动生成 |

---

## 性能优化

### 生产环境建议

```yaml
# 高性能配置
agentshield:
  # 启用缓存
  cache:
    enabled: true
    type: redis
    ttl: 300
    
  # 连接池
  pool:
    min_size: 10
    max_size: 100
    
  # 异步处理
  async:
    enabled: true
    workers: 4
```

### 资源规划

| 规模 | QPS | 内存 | CPU |
|------|-----|------|-----|
| 小型 | <100 | 512MB | 0.5 core |
| 中型 | 100-1000 | 2GB | 2 cores |
| 大型 | >1000 | 8GB+ | 8 cores+ |

---

## 安全加固

### 生产环境检查清单

- [ ] 使用 HTTPS
- [ ] 配置防火墙规则
- [ ] 启用审计日志
- [ ] 定期备份配置
- [ ] 设置强密码
- [ ] 限制 API 访问
- [ ] 监控资源使用
- [ ] 配置告警

### SSL/TLS 配置

```yaml
server:
  ssl:
    enabled: true
    cert_file: /path/to/cert.pem
    key_file: /path/to/key.pem
```

---

## 监控与运维

### 健康检查

```bash
# 检查服务状态
curl http://localhost:8000/health

# 检查就绪状态
curl http://localhost:8000/ready
```

### 日志管理

```bash
# 查看日志
docker-compose logs -f agentshield

# 使用 ELK stack
# 配置 Filebeat -> Logstash -> Elasticsearch -> Kibana
```

### 备份与恢复

```bash
# 备份配置
cp config.yaml config.yaml.backup

# 备份数据
docker-compose exec db pg_dump -U agentshield > backup.sql
```

---

## 故障排除

### 常见问题

| 问题 | 解决方案 |
|------|----------|
| 启动失败 | 检查配置文件语法 |
| 性能下降 | 增加 worker 数量 |
| 内存不足 | 调整 JVM 堆大小 |
| 连接超时 | 检查网络和防火墙 |

### 日志调试

```bash
# 开启调试模式
export LOG_LEVEL=DEBUG
python -m agentshield
```
