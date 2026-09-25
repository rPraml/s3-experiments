#!/usr/bin/env bash
# Start a local RustFS S3-compatible server for use with s3curl.sh.
#
# Usage:
#   ./rustfs-setup.sh
#   RUSTFS_ACCESS_KEY=myuser RUSTFS_SECRET_KEY='change-me' ./rustfs-setup.sh
#
# The container is deliberately kept running after this script exits.

set -euo pipefail

CONTAINER_NAME="${RUSTFS_CONTAINER_NAME:-rustfs-s3-test}"
IMAGE="${RUSTFS_IMAGE:-rustfs/rustfs:latest}"
ACCESS_KEY="${RUSTFS_ACCESS_KEY:-rustfsadmin}"
SECRET_KEY="${RUSTFS_SECRET_KEY:-rustfsadmin-secret}"
S3_PORT="${RUSTFS_S3_PORT:-9000}"
CONSOLE_PORT="${RUSTFS_CONSOLE_PORT:-9001}"
DATA_DIR="${RUSTFS_DATA_DIR:-$PWD/data}"
LOG_DIR="${RUSTFS_LOG_DIR:-$PWD/logs}"

command -v docker >/dev/null 2>&1 || {
    echo "ERROR: docker is required" >&2
    exit 1
}

mkdir -p "$DATA_DIR" "$LOG_DIR"
# RustFS runs as a non-root user inside the container. This also works when
# the host filesystem does not allow chown from the current user.
chmod u+rwx,go+rwx "$DATA_DIR" "$LOG_DIR"

if docker container inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    if [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME")" == "true" ]]; then
        echo "Container is already running: $CONTAINER_NAME"
    else
        docker start "$CONTAINER_NAME" >/dev/null
        echo "Container started: $CONTAINER_NAME"
    fi
else
    docker run -d \
        --name "$CONTAINER_NAME" \
        -p "${S3_PORT}:9000" \
        -p "${CONSOLE_PORT}:9001" \
        -e "RUSTFS_ACCESS_KEY=${ACCESS_KEY}" \
        -e "RUSTFS_SECRET_KEY=${SECRET_KEY}" \
        -v "${DATA_DIR}:/data" \
        -v "${LOG_DIR}:/logs" \
        "$IMAGE" >/dev/null
    echo "Container created and started: $CONTAINER_NAME"
fi

for _ in {1..30}; do
    # An unauthenticated request normally returns 403, which still proves
    # that the S3 HTTP service is listening and ready.
    if curl -sS -o /dev/null "http://127.0.0.1:${S3_PORT}/" 2>/dev/null; then
        break
    fi
    sleep 1
done

if ! curl -sS -o /dev/null "http://127.0.0.1:${S3_PORT}/" 2>/dev/null; then
    echo "ERROR: RustFS did not become ready on port ${S3_PORT}" >&2
    docker logs --tail 40 "$CONTAINER_NAME" >&2 || true
    exit 1
fi

cat <<EOF

RustFS is ready.

S3 endpoint:  http://127.0.0.1:${S3_PORT}
Console:     http://127.0.0.1:${CONSOLE_PORT}
Access key:  ${ACCESS_KEY}
Secret key:  ${SECRET_KEY}

Configure s3curl.sh in the current shell with:
  export AWS_ACCESS_KEY_ID='${ACCESS_KEY}'
  export AWS_SECRET_ACCESS_KEY='${SECRET_KEY}'
  export AWS_REGION='us-east-1'
  export S3_BUCKET='s3curl-test'
  export S3_ENDPOINT='http://127.0.0.1:${S3_PORT}'
  export S3_PATH_STYLE=1

Then create a bucket and test it:
  ./s3curl.sh mb
  ./s3curl.sh put test.txt dir1/test.txt
  ./s3curl.sh ls

Stop/remove the container later with:
  docker rm -f ${CONTAINER_NAME}
EOF
