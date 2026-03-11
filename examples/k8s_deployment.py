"""
AgentShield Kubernetes 部署示例

本示例展示如何配置 Helm values、deployment YAML 以及健康检查探针。
本文件是配置说明文档,包含 YAML 配置示例和解释。
"""

AGENTSHIELD_K8S_DEPLOYMENT_EXAMPLE = """
================================================================================
AgentShield Kubernetes 部署指南
================================================================================

本文件提供 AgentShield 在 Kubernetes 集群中部署的完整配置示例。

--------------------------------------------------------------------------------
1. Helm Values 配置 (values.yaml)
--------------------------------------------------------------------------------

# 基本配置
replicaCount: 3

image:
  repository: agentshield/agentshield
  pullPolicy: IfNotPresent
  tag: "0.5.0"

# 镜像拉取密钥 (私有仓库需要)
imagePullSecrets:
  - name: agentshield-registry-secret

# 服务账户
serviceAccount:
  create: true
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/AgentShieldRole

# Pod 注解 (用于 Prometheus 抓取指标)
podAnnotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "8083"
  prometheus.io/path: "/metrics"

# Pod 安全上下文
podSecurityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  seccompProfile:
    type: RuntimeDefault

# 容器安全上下文
securityContext:
  capabilities:
    drop:
    - ALL
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  privileged: false

# 服务配置
service:
  type: ClusterIP
  port: 8080           # 主服务端口
  livenessPort: 8081   # 存活探针端口
  readinessPort: 8082  # 就绪探针端口
  metricsPort: 8083   # Prometheus 指标端口

# 资源限制
resources:
  limits:
    cpu: 1000m
    memory: 1Gi
  requests:
    cpu: 250m
    memory: 256Mi

# 自动扩缩容
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80

# AgentShield 安全配置
config:
  firewall:
    enabled: true
    blockCritical: true
    blockHigh: true
    blockMedium: false
    detector:
      enabled_categories:
        - email
        - api_key_sk
        - password_in_url
        - sql_injection
        - xss_pattern
  toolManager:
    enabled: true
    enable_whitelist: true
    whitelist:
      - read_file
      - write_file
      - list_directory
  dataGateway:
    enabled: true
    enable_field_level_control: true
    enable_data_masking: true
  auditLogger:
    enabled: true
    persist_to_file: true
    logFilePath: "/var/log/agentshield/audit.log"
    max_events: 10000
  monitoring:
    prometheusEnabled: true
    healthCheckEnabled: true

# 持久化存储
persistence:
  enabled: true
  storageClass: "gp3"
  accessMode: ReadWriteOnce
  size: 10Gi

# Redis 配置 (用于会话存储)
redis:
  enabled: true
  architecture: standalone
  auth:
    enabled: true
    password: "changeme"

# Prometheus 配置
prometheus:
  enabled: true
  prometheusSpec:
    retention: 15d
    storageSpec:
      volumeClaimTemplate:
        spec:
          storageClassName: gp3
          resources:
            requests:
              storage: 50Gi

--------------------------------------------------------------------------------
2. Deployment YAML 详解
--------------------------------------------------------------------------------

apiVersion: apps/v1
kind: Deployment
metadata:
  name: agentshield
  labels:
    app: agentshield
    version: v1
spec:
  replicas: 3
  selector:
    matchLabels:
      app: agentshield
  template:
    metadata:
      labels:
        app: agentshield
        version: v1
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8083"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: agentshield
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: agentshield
        image: agentshield/agentshield:0.5.0
        imagePullPolicy: IfNotPresent

        ports:
        - name: http
          containerPort: 8080
          protocol: TCP
        - name: liveness
          containerPort: 8081
          protocol: TCP
        - name: readiness
          containerPort: 8082
          protocol: TCP
        - name: metrics
          containerPort: 8083
          protocol: TCP

        env:
        - name: AGENTSHIELD_CONFIG
          valueFrom:
            configMapKeyRef:
              name: agentshield-config
              key: config.yaml
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: agentshield-secrets
              key: redis-password

        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "1000m"

        livenessProbe:
          httpGet:
            path: /health/liveness
            port: 8081
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3

        readinessProbe:
          httpGet:
            path: /health/readiness
            port: 8082
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3

        startupProbe:
          httpGet:
            path: /health/startup
            port: 8081
          initialDelaySeconds: 5
          periodSeconds: 10
          timeoutSeconds: 3
          failureThreshold: 30

        volumeMounts:
        - name: audit-logs
          mountPath: /var/log/agentshield
        - name: tmp
          mountPath: /tmp

      volumes:
      - name: audit-logs
        persistentVolumeClaim:
          claimName: agentshield-pvc
      - name: tmp
        emptyDir: {}

      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchLabels:
                  app: agentshield
              topologyKey: kubernetes.io/hostname

      tolerations:
      - key: "dedicated"
        operator: "Equal"
        value: "agentshield"
        effect: "NoSchedule"

--------------------------------------------------------------------------------
3. 健康探针配置详解
--------------------------------------------------------------------------------

存活探针 (livenessProbe):
  - 用途: 检查容器是否存活,失败时重启容器
  - 端点: GET /health/liveness
  - 端口: 8081
  - initialDelaySeconds: 30  # 容器启动后等待30秒开始检查
  - periodSeconds: 10       # 每10秒检查一次
  - timeoutSeconds: 5        # 请求超时5秒
  - failureThreshold: 3      # 连续3次失败后重启容器

就绪探针 (readinessProbe):
  - 用途: 检查容器是否准备好接收流量
  - 端点: GET /health/readiness
  - 端口: 8082
  - initialDelaySeconds: 10  # 容器启动后等待10秒开始检查
  - periodSeconds: 5          # 每5秒检查一次
  - timeoutSeconds: 3         # 请求超时3秒
  - failureThreshold: 3       # 连续3次失败后从Service中移除

启动探针 (startupProbe):
  - 用途: 慢启动容器的健康检查
  - 端点: GET /health/startup
  - 端口: 8081
  - initialDelaySeconds: 5
  - periodSeconds: 10
  - timeoutSeconds: 3
  - failureThreshold: 30      # 允许最多300秒启动时间

--------------------------------------------------------------------------------
4. Service YAML 配置
--------------------------------------------------------------------------------

apiVersion: v1
kind: Service
metadata:
  name: agentshield
  labels:
    app: agentshield
spec:
  type: ClusterIP
  ports:
  - port: 8080
    targetPort: http
    protocol: TCP
    name: http
  - port: 8081
    targetPort: liveness
    protocol: TCP
    name: liveness
  - port: 8082
    targetPort: readiness
    protocol: TCP
    name: readiness
  - port: 8083
    targetPort: metrics
    protocol: TCP
    name: metrics
  selector:
    app: agentshield

--------------------------------------------------------------------------------
5. ConfigMap 配置
--------------------------------------------------------------------------------

apiVersion: v1
kind: ConfigMap
metadata:
  name: agentshield-config
data:
  config.yaml: |
    firewall:
      enabled: true
      block_critical: true
      block_high: true
      detector:
        enabled_categories:
          - email
          - phone
          - api_key_sk
          - sql_injection

    tool_manager:
      enabled: true
      enable_whitelist: true
      whitelist:
        - read_file
        - write_file

    data_gateway:
      enabled: true
      enable_field_level_control: true

    audit_logger:
      enabled: true
      persist_to_file: true
      log_file_path: /var/log/agentshield/audit.log

    monitoring:
      prometheus_enabled: true
      health_check_enabled: true

--------------------------------------------------------------------------------
6. Secret 配置
--------------------------------------------------------------------------------

apiVersion: v1
kind: Secret
metadata:
  name: agentshield-secrets
type: Opaque
stringData:
  redis-password: changeme
  jwt-secret: your-jwt-secret-key
  encryption-key: your-encryption-key

--------------------------------------------------------------------------------
7. Ingress 配置
--------------------------------------------------------------------------------

apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: agentshield
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  tls:
  - hosts:
    - agentshield.example.com
    secretName: agentshield-tls
  rules:
  - host: agentshield.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: agentshield
            port:
              number: 8080

--------------------------------------------------------------------------------
8. HorizontalPodAutoscaler 配置
--------------------------------------------------------------------------------

apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: agentshield
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: agentshield
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
      - type: Pods
        value: 4
        periodSeconds: 15
      selectPolicy: Max

--------------------------------------------------------------------------------
9. PodDisruptionBudget 配置
--------------------------------------------------------------------------------

apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: agentshield
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: agentshield

--------------------------------------------------------------------------------
10. 网络策略配置
--------------------------------------------------------------------------------

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agentshield
spec:
  podSelector:
    matchLabels:
      app: agentshield
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: production
    ports:
    - protocol: TCP
      port: 8080
  - from:
    - podSelector:
        matchLabels:
          app: prometheus
    ports:
    - protocol: TCP
      port: 8083
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - protocol: TCP
      port: 6379
  - to:
    - namespaceSelector: {}

================================================================================
部署命令
================================================================================

# 添加 Helm 仓库
helm repo add agentshield https://agentshield.github.io/helm-charts
helm repo update

# 安装 AgentShield
helm install agentshield agentshield/agentshield \\
  --namespace agentshield \\
  --create-namespace \\
  --values values.yaml

# 升级 AgentShield
helm upgrade agentshield agentshield/agentshield \\
  --namespace agentshield \\
  --values values.yaml

# 查看部署状态
kubectl get pods -n agentshield
kubectl get svc -n agentshield

# 查看日志
kubectl logs -n agentshield -l app=agentshield -f

# 查看指标
kubectl port-forward -n agentshield svc/agentshield 8083:8083
curl http://localhost:8083/metrics

# 健康检查
curl http://localhost:8081/health/liveness
curl http://localhost:8082/health/readiness
"""


def main():
    print("=" * 70)
    print("AgentShield Kubernetes 部署示例")
    print("=" * 70)

    print(AGENTSHIELD_K8S_DEPLOYMENT_EXAMPLE)

    print("\n" + "=" * 70)
    print("配置说明总结")
    print("=" * 70)

    config_explanations = {
        "Helm Values": {
            "replicaCount": "Pod 副本数量,建议生产环境设置为 3 或更多",
            "image": "容器镜像配置,包括仓库地址和标签",
            "resources": "CPU 和内存资源限制,确保容器有足够资源运行",
            "autoscaling": "HPA 自动扩缩容配置,根据 CPU/内存使用率调整副本数",
            "config": "AgentShield 各个安全组件的启用和配置",
            "persistence": "持久化存储配置,用于保存审计日志等数据",
        },
        "Deployment": {
            "livenessProbe": "存活探针检测容器是否存活,失败时重启",
            "readinessProbe": "就绪探针检测是否准备好接收流量",
            "startupProbe": "启动探针用于慢启动应用",
            "securityContext": "容器安全上下文,包括非 root 用户运行",
            "affinity": "Pod 亲和性配置,避免单点故障",
        },
        "Service": {
            "port": "主服务端口 (8080)",
            "livenessPort": "存活探针专用端口 (8081)",
            "readinessPort": "就绪探针专用端口 (8082)",
            "metricsPort": "Prometheus 指标端口 (8083)",
        },
        "Monitoring": {
            "Prometheus": "自动发现和抓取 /metrics 端点",
            "Annotations": "podAnnotations 配置 Prometheus 抓取参数",
        },
    }

    for category, items in config_explanations.items():
        print(f"\n{category}:")
        for key, desc in items.items():
            print(f"  • {key}: {desc}")

    print("\n" + "=" * 70)
    print("快速部署命令")
    print("=" * 70)
    print("""
# 1. 使用 Helm 快速部署
helm install agentshield agentshield/agentshield --namespace agentshield --create-namespace

# 2. 使用自定义配置部署
helm install agentshield agentshield/agentshield -f custom-values.yaml

# 3. 查看状态
kubectl get pods -n agentshield -w

# 4. 访问服务
kubectl port-forward -n agentshield svc/agentshield 8080:8080

# 5. 查看指标
curl http://localhost:8083/metrics
""")

    print("=" * 70)
    print("K8s 部署示例完成!")
    print("=" * 70)


if __name__ == "__main__":
    main()
