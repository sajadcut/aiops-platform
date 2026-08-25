ARG PYTHON_BASE_IMAGE=python:3.12-slim
FROM ${PYTHON_BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN addgroup --system aiops \
    && adduser --system --ingroup aiops --uid 10001 aiops

WORKDIR /app

# Offline production contract: the approved base image/build environment must
# provide the complete wheelhouse at /opt/wheels. Missing dependencies fail the
# image build; a partially installed runtime is never accepted.
COPY requirements.txt ./
RUN test -d /opt/wheels \
    && python -m pip install --no-index --find-links=/opt/wheels -r requirements.txt \
    && python -m pip check

COPY --chown=aiops:aiops . .

USER 10001:10001

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
