# Preflight in a container, for people who'd rather not install anything -
# or who want the scan to run somewhere with no access to the rest of their
# machine.
#
#   docker run --rm -v "$HOME/.aws:/home/preflight/.aws:ro" \
#     ghcr.io/jetonecloud/preflight:latest demo
#
# Built from the wheel rather than the PyInstaller binary: the binary is
# built per-platform on a matrix of runners, and a container already has a
# Python to run, so there's nothing for PyInstaller to add here.

FROM python:3.12-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# A virtualenv so the final stage can take the whole thing in one COPY,
# without pip, its caches, or the build backend coming along.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /src
# Only what the build backend reads. Keeping the tests and docs out means a
# docs change doesn't invalidate the layer that installs the dependencies.
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install .


FROM python:3.12-slim

# Set by the release workflow from the tag; only the labels use it, so a
# local `docker build` with no --build-arg still produces a working image.
ARG VERSION=0.0.0-dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="Preflight" \
      org.opencontainers.image.description="Read-only AWS audit CLI: what to fix in deploys, cost, and bus factor." \
      org.opencontainers.image.url="https://github.com/jetonecloud/preflight" \
      org.opencontainers.image.source="https://github.com/jetonecloud/preflight" \
      org.opencontainers.image.documentation="https://github.com/jetonecloud/preflight/blob/main/docs/installation.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Jet1" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY --from=build /opt/venv /opt/venv

# Nothing here needs root, and a tool that reads someone's AWS credentials
# is the last thing that should ask for it. uid 1000 is the usual first
# human account, so a bind-mounted ~/.aws and a writable output directory
# line up without --user on most hosts.
RUN useradd --create-home --uid 1000 preflight \
    && mkdir /out \
    && chown preflight:preflight /out

USER preflight

# Where the report and the JSON export land by default: `--out` defaults to
# the working directory, so `-v "$PWD:/out"` is all a caller needs.
WORKDIR /out

ENTRYPOINT ["preflight"]
CMD ["--help"]
