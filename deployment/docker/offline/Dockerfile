ARG PYTHON_BASE_IMAGE=python:3.12-slim
FROM ${PYTHON_BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    APP_ENV=production \
    LOG_DIR=/var/log/aiops

RUN addgroup --system aiops \
    && adduser --system --ingroup aiops --uid 10001 aiops \
    && mkdir -p /var/log/aiops \
    && chown -R aiops:aiops /var/log/aiops

WORKDIR /app

# Offline production contract: the approved base image/build environment must
# provide the complete wheelhouse at /opt/wheels. Missing dependencies fail the
# image build; a partially installed runtime is never accepted.
COPY requirements.txt ./
RUN test -d /opt/wheels \
    && python -m pip install --no-index --find-links=/opt/wheels -r requirements.txt \
    && python -m pip check \
    && current_openssl="$(dpkg-query -W -f='${Version}' openssl)" \
    && dpkg --compare-versions "$current_openssl" ge '3.5.7-1~deb13u2' \
    && python - <<'PY'
from importlib.metadata import PackageNotFoundError, version
from packaging.version import Version

minimums = {"setuptools": "78.1.1", "msgpack": "1.2.1"}
for package, minimum in minimums.items():
    try:
        installed = version(package)
    except PackageNotFoundError:
        continue
    if Version(installed) < Version(minimum):
        raise SystemExit(f"vulnerable runtime package: {package}={installed} < {minimum}")
PY

RUN rm -rf /root/.cache/pip

# .dockerignore excludes .env, VCS metadata, logs and local artifacts. Runtime
# secrets/configuration are injected by the deployment platform, never baked.
COPY --chown=aiops:aiops . .

USER 10001:10001

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health/live', timeout=3).read()" || exit 1

CMD ["python", "-m", "uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
