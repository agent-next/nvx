set -eu
fail() {
    code="$1"
    echo "NVX-FILESYSTEM-POLICY-FAIL code=$code"
    nvx-exit "$code"
    exit "$code"
}

expect_read_only() {
    case "$1" in
        *'Read-only file system'*) ;;
        *)
            echo "NVX-FILESYSTEM-POLICY-ERROR $1"
            fail "$2"
            ;;
    esac
}

# The share is mounted read-write, and only OpenVMM narrows its writes.
grep -q 'virtfs_dir=/workspace virtfs_tag=microvm virtfs_mode=rw' /proc/cmdline || fail 40
grep -q '^microvm /workspace virtiofs rw' /proc/mounts || fail 41
[ "$(cat /workspace/seed)" = NVX-SEED ] || fail 42

# The writable paths accept the guest's writes.
printf 'NVX-GUEST-WRITE\n' >/workspace/out/from-guest || fail 43
mkdir /workspace/out/guest-directory || fail 44
printf 'nested\n' >/workspace/out/guest-directory/file || fail 45
mv /workspace/out/guest-directory/file /workspace/out/renamed || fail 46
rmdir /workspace/out/guest-directory || fail 47
ln -s ../seed /workspace/out/seed-link || fail 48
printf 'APPEND' >>/workspace/build.log || fail 49

# Everywhere else, OpenVMM rejects every mutation with EROFS, even from guest
# root, whose permission checks the mode bits never stop.
if error=$(touch /workspace/mutation 2>&1); then
    fail 50
fi
expect_read_only "$error" 51
if error=$(mkdir /workspace/directory 2>&1); then
    fail 52
fi
expect_read_only "$error" 53
if error=$( (printf 'append\n' >>/workspace/seed) 2>&1); then
    fail 54
fi
expect_read_only "$error" 55
if error=$(rm -f /workspace/seed 2>&1); then
    fail 56
fi
expect_read_only "$error" 57
if error=$(chmod 0777 /workspace/seed 2>&1); then
    fail 58
fi
expect_read_only "$error" 59
if error=$(ln -s seed /workspace/link 2>&1); then
    fail 60
fi
expect_read_only "$error" 61
if error=$(rm -f /workspace/build.log 2>&1); then
    fail 62
fi
expect_read_only "$error" 63
if error=$(rmdir /workspace/out 2>&1); then
    fail 64
fi
expect_read_only "$error" 65
# Moving an entry into or out of a writable path changes a read-only
# directory.
if error=$(mv /workspace/seed /workspace/out/seed 2>&1); then
    fail 66
fi
expect_read_only "$error" 67
if error=$(mv /workspace/out/renamed /workspace/renamed 2>&1); then
    fail 68
fi
expect_read_only "$error" 69
# A hard link in a writable path would make a read-only file writable.
if error=$(ln /workspace/seed /workspace/out/seed-hard 2>&1); then
    fail 70
fi
case "$error" in
    *ross-device*) ;;
    *)
        echo "NVX-FILESYSTEM-POLICY-ERROR $error"
        fail 71
        ;;
esac

# The denied directory lists only the way to the allowed path, which stays
# readable, and the denied path inside the allowed path stays hidden.
[ "$(ls -A /workspace/logs)" = payloads ] || fail 72
[ "$(ls -A /workspace/logs/payloads)" = payload ] || fail 73
[ "$(cat /workspace/logs/payloads/payload)" = NVX-PAYLOAD ] || fail 74
for hidden in /workspace/logs/secret /workspace/logs/gateway/log \
    /workspace/logs/payloads/private/key; do
    if cat "$hidden" >/dev/null 2>&1; then
        fail 75
    fi
done
if (cd /workspace/logs/payloads && cat ../secret) >/dev/null 2>&1; then
    fail 76
fi
if touch /workspace/logs/mutation 2>/dev/null; then
    fail 77
fi
# The allowed path follows the write policy, so it is read-only here.
if error=$(touch /workspace/logs/payloads/mutation 2>&1); then
    fail 78
fi
expect_read_only "$error" 79
if error=$(mv /workspace/logs /workspace/out/logs 2>&1); then
    fail 80
fi
expect_read_only "$error" 81
# A link that the guest resolves cannot reach a hidden path.
ln -s ../logs/secret /workspace/out/secret-link || fail 82
if cat /workspace/out/secret-link >/dev/null 2>&1; then
    fail 83
fi
rm /workspace/out/secret-link || fail 84

# OpenVMM, not the guest mount, enforces the policy for every mount of the tag.
mkdir -p /mnt/second
mount -t virtiofs microvm /mnt/second || fail 85
if error=$(touch /mnt/second/mutation 2>&1); then
    fail 86
fi
expect_read_only "$error" 87
if cat /mnt/second/logs/secret >/dev/null 2>&1; then
    fail 88
fi
[ "$(cat /mnt/second/logs/payloads/payload)" = NVX-PAYLOAD ] || fail 89
umount /mnt/second || fail 90

echo NVX-FILESYSTEM-POLICY-OK
nvx-exit 0
