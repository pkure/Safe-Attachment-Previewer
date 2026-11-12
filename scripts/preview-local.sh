#!/usr/bin/env bash
# hal-id: #HAL-20261110-0012-PK-S4
# Local safe-render prototype (no cloud, $0). Needs Docker.
#   preview-local.sh build            build the engine image
#   preview-local.sh samples          generate the benign test samples into dist/samples-v2
#   preview-local.sh test             run unit + end-to-end tests inside the offline container
#   preview-local.sh render FILE...   render one case and open it in the viewer
#   preview-local.sh serve            just serve the viewer (http://127.0.0.1:8765)
#   preview-local.sh lockdown-proof   WITH the network on: show the container can reach the internet, then show
#                                     the locked renderer can't (the cloud setup, where --network none isn't available)
set -euo pipefail
cd "$(dirname "$0")/.."
IMG=saferender:dev
PREVIEW=.preview
PORT=8765
# The isolation contract. Same flags the cloud job uses (no network, read-only, no privileges, capped).
HARDEN=(--rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=1g --cap-drop ALL
        --security-opt no-new-privileges --pids-limit 256 --memory 2g --cpus 2 --user 10001:10001)

serve() {
  rsync -a --delete --exclude cases viewer/ "$PREVIEW/"
  if ! curl -s -o /dev/null "http://127.0.0.1:$PORT/"; then
    (cd "$PREVIEW" && nohup python3 -I -m http.server "$PORT" --bind 127.0.0.1 </dev/null >/dev/null 2>&1 & disown) >/dev/null 2>&1
    sleep 1
  fi
}

case "${1:-}" in
  build) docker build -t "$IMG" saferender ;;
  samples)
    mkdir -p dist/samples-v2 && chmod a+rwx dist/samples-v2  # container runs as uid 10001 (matters on Linux)
    docker run "${HARDEN[@]}" -v "$PWD/dist/samples-v2:/out" --entrypoint python "$IMG" -m saferender.make_samples /out
    ;;
  test)
    mkdir -p dist/all-samples && cp dist/samples/* dist/samples-v2/* dist/all-samples/
    docker run "${HARDEN[@]}" -v "$PWD/dist/all-samples:/samples:ro" -e SAMPLES=/samples --entrypoint python "$IMG" \
      -m pytest -q -p no:cacheprovider /app/tests "${@:2}"
    ;;
  render)
    shift
    [[ $# -gt 0 ]] || { echo "usage: $0 render FILE..."; exit 1; }
    id="$(date -u +%Y%m%d-%H%M%S)-$(openssl rand -hex 2)"
    in="$(mktemp -d)"
    cp "$@" "$in/"
    mkdir -p "$PREVIEW/cases/$id" && chmod a+rwx "$PREVIEW/cases/$id"
    docker run "${HARDEN[@]}" -v "$in:/in:ro" -v "$PWD/$PREVIEW/cases/$id:/out" "$IMG" --case "$id"
    rm -rf "$in"
    serve
    echo "viewer: http://127.0.0.1:$PORT/?case=$id"
    open "http://127.0.0.1:$PORT/?case=$id" 2>/dev/null || true
    ;;
  serve) serve; echo "http://127.0.0.1:$PORT/" ;;
  lockdown-proof)
    # Same hardening EXCEPT the network: this is what a cloud container looks like.
    docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=1g --cap-drop ALL --security-opt no-new-privileges \
      --pids-limit 256 --memory 2g --cpus 2 --user 10001:10001 --entrypoint python "$IMG" -c '
import json, socket, subprocess, sys
from saferender import lockdown
def reach():
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=5).close(); net = "REACHABLE"
    except OSError as e:
        net = f"unreachable ({e.strerror})"
    try:
        socket.getaddrinfo("www.microsoft.com", 443); dns = "RESOLVES"
    except OSError:
        dns = "fails"
    return net, dns
print("container (fetcher side), no lock:  internet %s, DNS %s" % reach())
print("renderer side, under the lock:      ", json.dumps(lockdown.verify()["probe"]))
'
    ;;
  *) sed -n '3,11p' "$0"; exit 1 ;;
esac
