set -eu
fail() {
    code="$1"
    echo "NVX-FILESYSTEM-OWNER-FAIL code=$code"
    nvx-exit "$code"
    exit "$code"
}

# Without CAP_SETUID and CAP_SETGID, OpenVMM fails every request on a
# caller-identity share with EPERM instead of using its own identity.
grep -q ' /mnt/share virtiofs ' /proc/mounts || fail 160
if error=$(cat /mnt/share/host-marker 2>&1); then
    fail 161
fi
case "$error" in
    *"Operation not permitted"*) ;;
    *) fail 162 ;;
esac
if error=$(touch /mnt/share/guest-file 2>&1); then
    fail 163
fi
case "$error" in
    *"Operation not permitted"*) ;;
    *) fail 164 ;;
esac
if mkdir /mnt/share/guest-directory 2>/dev/null; then
    fail 165
fi

echo NVX-FILESYSTEM-OWNER-DENIED-OK
nvx-exit 0
