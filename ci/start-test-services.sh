#!/usr/bin/env bash
# ci/start-test-services.sh: start a real PostgreSQL and a real Redis as
# unprivileged local subprocesses, for the `test-integration` job.
#
# Why not GitHub Actions `services:` containers? The `lab` ARC runner pods
# have no Docker daemon, ever. They also run as user `runner` (uid 1000) with
# no root and no sudo, so `apt-get install postgresql redis` is impossible and
# neither package is baked into the shared runner image.
#
# So we fetch relocatable prebuilt binaries that run from the workspace as an
# ordinary user. These are real servers, not fakes: the tests still speak the
# PostgreSQL and Redis wire protocols to real postgres and real redis.
#
#   postgres  zonky embedded-postgres-binaries, the same relocatable build
#             the JVM embedded-postgres projects use. Ships contrib modules,
#             including pgcrypto, which our migrations need. Note it contains
#             only initdb/pg_ctl/postgres (no psql/createdb), which is why the
#             database is created via single-user mode below.
#   redis     conda-forge's redis-server package. Its modern .conda archive is
#             zstd-compressed and the runner image has no zstd, so zstd is
#             first bootstrapped from a legacy bzip2-compressed conda package.
#
# Versions are pinned and track the container images this job used to run
# (postgres:16 and redis:7).
#
# Usage:  bash ci/start-test-services.sh
#
# Leaves running:
#   postgres  127.0.0.1:5432   user postgres, trust auth, database deep_analysis
#   redis     127.0.0.1:6379
#
# Locally, stop them with:
#   "$DA_TEST_SERVICES_DIR/pgsql/bin/pg_ctl" -D "$DA_TEST_SERVICES_DIR/pgdata" stop
#   "$DA_TEST_SERVICES_DIR/redis/bin/redis-cli" -p 6379 shutdown nosave

set -euo pipefail

PG_VERSION="16.4.0"
REDIS_CONDA_PKG="redis-server-7.4.7-h35e630c_0"
ZSTD_CONDA_PKG="zstd-1.5.2-h8a70e8d_4"

PG_PORT="${PG_PORT:-5432}"
REDIS_PORT="${REDIS_PORT:-6379}"
PG_DB="${PG_DB:-deep_analysis}"
PG_USER="${PG_USER:-postgres}"

ROOT="${DA_TEST_SERVICES_DIR:-${RUNNER_TEMP:-/tmp}/da-test-services}"
mkdir -p "$ROOT"
cd "$ROOT"

echo "==> test services root: $ROOT"

# --- PostgreSQL ------------------------------------------------------------

PG_HOME="$ROOT/pgsql"
PGDATA="$ROOT/pgdata"

if [ ! -x "$PG_HOME/bin/postgres" ]; then
  echo "==> fetching postgres ${PG_VERSION}"
  curl -fsSL -o "$ROOT/postgres.jar" \
    "https://repo1.maven.org/maven2/io/zonky/test/postgres/embedded-postgres-binaries-linux-amd64/${PG_VERSION}/embedded-postgres-binaries-linux-amd64-${PG_VERSION}.jar"
  mkdir -p "$PG_HOME"
  unzip -p "$ROOT/postgres.jar" postgres-linux-x86_64.txz | tar -xJ -C "$PG_HOME"
  rm -f "$ROOT/postgres.jar"
fi

export PATH="$PG_HOME/bin:$PATH"
postgres --version

if [ ! -s "$PGDATA/PG_VERSION" ]; then
  echo "==> initdb"
  rm -rf "$PGDATA"
  initdb -D "$PGDATA" -U "$PG_USER" --auth=trust -E UTF8 --locale=C >"$ROOT/initdb.log" 2>&1 \
    || { tail -n 40 "$ROOT/initdb.log"; exit 1; }

  # The zonky build ships no psql/createdb, so create the database offline in
  # single-user mode before the server is started.
  echo "CREATE DATABASE ${PG_DB};" \
    | postgres --single -D "$PGDATA" postgres >"$ROOT/createdb.log" 2>&1 \
    || { tail -n 40 "$ROOT/createdb.log"; exit 1; }
fi

echo "==> starting postgres on 127.0.0.1:${PG_PORT}"
pg_ctl -D "$PGDATA" -l "$ROOT/postgres.log" -w start \
  -o "-p ${PG_PORT} -k ${ROOT} -c listen_addresses=127.0.0.1" \
  || { tail -n 60 "$ROOT/postgres.log"; exit 1; }

# --- Redis -----------------------------------------------------------------

REDIS_HOME="$ROOT/redis"

if [ ! -x "$REDIS_HOME/bin/redis-server" ]; then
  echo "==> bootstrapping zstd (needed to read the .conda archive)"
  ZSTD_HOME="$ROOT/zstd"
  mkdir -p "$ZSTD_HOME"
  curl -fsSL -o "$ROOT/zstd.tar.bz2" \
    "https://conda.anaconda.org/conda-forge/linux-64/${ZSTD_CONDA_PKG}.tar.bz2"
  tar -xjf "$ROOT/zstd.tar.bz2" -C "$ZSTD_HOME"
  rm -f "$ROOT/zstd.tar.bz2"

  echo "==> fetching redis (${REDIS_CONDA_PKG})"
  curl -fsSL -o "$ROOT/redis.conda" \
    "https://conda.anaconda.org/conda-forge/linux-64/${REDIS_CONDA_PKG}.conda"
  mkdir -p "$ROOT/redis-conda" "$REDIS_HOME"
  unzip -o -q "$ROOT/redis.conda" -d "$ROOT/redis-conda"
  LD_LIBRARY_PATH="$ZSTD_HOME/lib" \
    tar --use-compress-program="$ZSTD_HOME/bin/unzstd" \
        -xf "$ROOT/redis-conda/pkg-${REDIS_CONDA_PKG}.tar.zst" -C "$REDIS_HOME"
  rm -rf "$ROOT/redis.conda" "$ROOT/redis-conda"
fi

"$REDIS_HOME/bin/redis-server" --version

echo "==> starting redis on 127.0.0.1:${REDIS_PORT}"
"$REDIS_HOME/bin/redis-server" \
  --port "$REDIS_PORT" \
  --bind 127.0.0.1 \
  --daemonize yes \
  --save '' \
  --dir "$ROOT" \
  --logfile "$ROOT/redis.log"

for _ in $(seq 1 30); do
  if [ "$("$REDIS_HOME/bin/redis-cli" -h 127.0.0.1 -p "$REDIS_PORT" ping 2>/dev/null)" = "PONG" ]; then
    echo "==> redis ready"
    exit 0
  fi
  sleep 1
done

echo "redis never answered PING" >&2
tail -n 60 "$ROOT/redis.log" >&2 || true
exit 1
