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
# (postgres:16 and redis:7). Every download is checked against a pinned
# SHA-256 before it is extracted or executed: see the digest block below.
# Caveat: both fetch blocks are skipped entirely when an already-extracted
# tree is present, so pointing DA_TEST_SERVICES_DIR at a shared or persisted
# cache trusts whatever is already in it. The ARC runner pods this targets
# are ephemeral, so in CI every run re-downloads and re-verifies.
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

# Expected SHA-256 of every archive this script downloads. A versioned URL
# pins a name, not the bytes: without these, altered upstream content would be
# extracted and executed on a runner pool shared by every repo in the org.
#
# To update after a version bump: change the version pin above, download the
# new URL by hand, run `sha256sum <file>`, and paste the digest here. Then
# confirm it against upstream-published metadata before trusting it, do not
# just take your own download's word for it. The digests below were each
# confirmed this way:
#   maven  curl -fsSL "<jar-url>.sha256"  (repo1.maven.org publishes .sha256
#          and .sha1 sidecars next to every artifact)
#   conda  curl -fsSL "https://api.anaconda.org/package/conda-forge/<name>/files"
#          and read the "sha256" of the matching linux-64 basename. Older
#          .tar.bz2 uploads (zstd here) record only "md5", so cross-check that
#          field with `md5sum` instead and pin the sha256 of those same bytes.
# Never "fix" a mismatch by pasting in whatever the download hashed to.
PG_JAR_SHA256="14a5cf546aee7d327a2f5b46be6c571f2f724a2b485c270d46f3e44a1ac3df18"
REDIS_CONDA_SHA256="c49d1f8c19a5f045bf7526825429fd94c520e2081c1246734301aeb2006aa6b6"
ZSTD_CONDA_SHA256="e1d73591ba6caef2a30ff0fc85414f5aef4ac50fb23c7f1e5beb49d8133a2ec4"

# verify_sha256 <file> <expected> <what>
# Fails the script immediately on mismatch, before anything is extracted or
# executed, naming the file and both digests.
verify_sha256() {
  local file="$1" expected="$2" what="$3" actual
  actual="$(sha256sum "$file" | awk '{print $1}')"
  if [ "$actual" != "$expected" ]; then
    echo "" >&2
    echo "FATAL: checksum mismatch for ${what}" >&2
    echo "  file:     ${file}" >&2
    echo "  expected: ${expected}" >&2
    echo "  actual:   ${actual}" >&2
    echo "" >&2
    echo "Refusing to extract or execute unverified bytes. Either the pinned" >&2
    echo "version changed upstream or the download was tampered with. See the" >&2
    echo "digest-update comment near the top of ci/start-test-services.sh." >&2
    rm -f "$file"
    exit 1
  fi
  echo "==> verified ${what} sha256 ${actual}"
}

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
  verify_sha256 "$ROOT/postgres.jar" "$PG_JAR_SHA256" "embedded-postgres-binaries-linux-amd64-${PG_VERSION}.jar"
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
  verify_sha256 "$ROOT/zstd.tar.bz2" "$ZSTD_CONDA_SHA256" "${ZSTD_CONDA_PKG}.tar.bz2"
  tar -xjf "$ROOT/zstd.tar.bz2" -C "$ZSTD_HOME"
  rm -f "$ROOT/zstd.tar.bz2"

  echo "==> fetching redis (${REDIS_CONDA_PKG})"
  curl -fsSL -o "$ROOT/redis.conda" \
    "https://conda.anaconda.org/conda-forge/linux-64/${REDIS_CONDA_PKG}.conda"
  verify_sha256 "$ROOT/redis.conda" "$REDIS_CONDA_SHA256" "${REDIS_CONDA_PKG}.conda"
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
