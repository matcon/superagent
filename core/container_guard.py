"""
core/container_guard.py - Container & Cloud-Native Security Validator and Production Generator
Audits Dockerfiles, Kubernetes manifests, and Docker Compose configurations against DevSecOps standards.
"""

import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class ContainerViolation:
    rule_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    line: Optional[int] = None
    remediation: str = ""


@dataclass
class ContainerAuditReport:
    file_path: str
    target_type: str  # dockerfile, k8s, compose
    passed: bool
    violations: List[ContainerViolation] = field(default_factory=list)


class ContainerGuard:
    """Validador y generador de configuraciones de contenedores endurecidos para producción."""

    @classmethod
    def audit_dockerfile(cls, content: str, file_path: str = "Dockerfile") -> ContainerAuditReport:
        lines = content.splitlines()
        violations: List[ContainerViolation] = []

        has_user = False
        has_healthcheck = False
        from_stages = 0
        has_latest = False

        for idx, line in enumerate(lines, 1):
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue

            # Check FROM
            if clean.upper().startswith("FROM "):
                from_stages += 1
                if ":latest" in clean.lower():
                    has_latest = True
                    violations.append(ContainerViolation(
                        rule_id="DOCK-001",
                        severity="MEDIUM",
                        line=idx,
                        description="Uso de la etiqueta mutable ':latest' en imagen base",
                        remediation="Especifique un tag de versión inmutable o digest SHA256 (ej. python:3.12-slim)."
                    ))

            # Check USER
            if clean.upper().startswith("USER "):
                val = clean[5:].strip()
                if val not in ["root", "0"]:
                    has_user = True
                else:
                    violations.append(ContainerViolation(
                        rule_id="DOCK-002",
                        severity="CRITICAL",
                        line=idx,
                        description="Directiva USER explícita para root o UID 0",
                        remediation="Cree un usuario sin privilegios y configúrelo antes de CMD/ENTRYPOINT."
                    ))

            # Check Secrets in ENV or ARG
            if clean.upper().startswith("ENV ") or clean.upper().startswith("ARG "):
                if re.search(r"(?i)(password|secret|token|api_key)\s*=", clean):
                    violations.append(ContainerViolation(
                        rule_id="DOCK-003",
                        severity="CRITICAL",
                        line=idx,
                        description="Posible secreto embebido en directiva ENV o ARG",
                        remediation="Nunca guarde credenciales en la imagen. Consúmalas en runtime vía variables de entorno o volúmenes montados."
                    ))

            # Check HEALTHCHECK
            if clean.upper().startswith("HEALTHCHECK "):
                has_healthcheck = True

        if not has_user:
            violations.append(ContainerViolation(
                rule_id="DOCK-004",
                severity="HIGH",
                description="Ausencia de directiva USER no-root (el contenedor se ejecutará como root por defecto)",
                remediation="Agregue 'USER nonroot' o un usuario con UID >= 10001."
            ))

        if from_stages < 2:
            violations.append(ContainerViolation(
                rule_id="DOCK-005",
                severity="LOW",
                description="No se detectó Multi-Stage Build (FROM ... AS ...)",
                remediation="Considere un build multi-etapa para mantener el runtime final libre de herramientas de compilación."
            ))

        passed = not any(v.severity in ["CRITICAL", "HIGH"] for v in violations)
        return ContainerAuditReport(file_path=file_path, target_type="dockerfile", passed=passed, violations=violations)

    @classmethod
    def generate_dockerfile(cls, stack: str = "python") -> str:
        """Sintetiza un Dockerfile endurecido con arquitectura Multi-Stage y distroless/nonroot."""
        if stack.lower() == "python":
            return """# syntax=docker/dockerfile:1.4
# Multi-Stage Production Dockerfile for Python
FROM python:3.12-slim AS builder

WORKDIR /build
ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Runtime Stage (Minimal & Non-Root)
FROM python:3.12-slim AS runner

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    PATH="/home/appuser/.local/bin:$PATH"

# Create unprivileged system user
RUN groupadd -g 10001 appgroup && \\
    useradd -u 10001 -g appgroup -s /sbin/nologin -m appuser

# Copy installed dependencies and application code
COPY --from=builder /root/.local /home/appuser/.local
COPY --chown=appuser:appgroup . /app

USER appuser:appgroup
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \\
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

ENTRYPOINT ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
"""
        elif stack.lower() in ["node", "typescript", "ts"]:
            return """# syntax=docker/dockerfile:1.4
# Multi-Stage Production Dockerfile for Node.js
FROM node:20-alpine AS builder

WORKDIR /usr/src/app
COPY package*.json tsconfig.json ./
RUN npm ci --ignore-scripts

COPY src/ ./src
RUN npm run build && npm prune --omit=dev

# Runtime Stage (Distroless Nonroot)
FROM gcr.io/distroless/nodejs20-debian12:nonroot AS runner

WORKDIR /app
ENV NODE_ENV=production

COPY --from=builder --chown=nonroot:nonroot /usr/src/app/node_modules ./node_modules
COPY --from=builder --chown=nonroot:nonroot /usr/src/app/dist ./dist
COPY --from=builder --chown=nonroot:nonroot /usr/src/app/package.json ./package.json

USER nonroot
EXPOSE 3000

ENTRYPOINT ["/nodejs/bin/node", "dist/index.js"]
"""
        elif stack.lower() in ["go", "golang"]:
            return """# syntax=docker/dockerfile:1.4
# Multi-Stage Production Dockerfile for Go
FROM golang:1.23-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /bin/app .

# Distroless Static Runtime
FROM gcr.io/distroless/static-debian12:nonroot AS runner

WORKDIR /
COPY --from=builder --chown=nonroot:nonroot /bin/app /bin/app

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/bin/app"]
"""
        else:
            raise ValueError(f"Stack '{stack}' no soportado para generación automática.")

    @classmethod
    def generate_k8s_manifest(cls, app_name: str = "app", image: str = "app:latest", port: int = 8080) -> str:
        """Genera un manifiesto de Kubernetes con PodSecurityStandards Restricted y Zero-Downtime RollingUpdate."""
        return f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: {app_name}
  labels:
    app.kubernetes.io/name: {app_name}
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 0
  selector:
    matchLabels:
      app: {app_name}
  template:
    metadata:
      labels:
        app: {app_name}
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: {app_name}
          image: {image}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          ports:
            - containerPort: {port}
              name: http
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
          livenessProbe:
            httpGet:
              path: /health
              port: {port}
            periodSeconds: 15
            timeoutSeconds: 3
          readinessProbe:
            httpGet:
              path: /ready
              port: {port}
            periodSeconds: 10
            timeoutSeconds: 2
---
apiVersion: v1
kind: Service
metadata:
  name: {app_name}-svc
spec:
  selector:
    app: {app_name}
  ports:
    - protocol: TCP
      port: 80
      targetPort: {port}
"""
