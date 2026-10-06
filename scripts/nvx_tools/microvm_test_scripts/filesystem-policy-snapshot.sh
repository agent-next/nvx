set -eu
fail() {
    code="$1"
    echo "NVX-FILESYSTEM-POLICY-SNAPSHOT-FAIL code=$code"
    nvx-exit "$code"
    exit "$code"
}

grep -q '^microvm /workspace virtiofs rw' /proc/mounts || fail 100
# A handle open for writing in a writable path survives the snapshot.
exec 3<>/workspace/out/journal
printf NVX-BEFORE >&3
echo NVX-FILESYSTEM-POLICY-BEFORE
nvx-snapshot
printf NVX-AFTER >&3
exec 3>&-
[ "$(cat /workspace/out/journal)" = NVX-BEFORENVX-AFTER ] || fail 101
# The restored share keeps its access policy.
if touch /workspace/mutation 2>/dev/null; then
    fail 102
fi
[ "$(ls -A /workspace/logs)" = payloads ] || fail 103
[ "$(cat /workspace/logs/payloads/payload)" = NVX-PAYLOAD ] || fail 104
if cat /workspace/logs/secret >/dev/null 2>&1; then
    fail 105
fi
echo NVX-FILESYSTEM-POLICY-AFTER
nvx-exit 0
