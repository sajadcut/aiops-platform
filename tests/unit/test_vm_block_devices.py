"""Block inventory parsing is read-only, bounded and never invents mounts."""
from integrations.vm.block_devices import parse_block_devices, parse_mount_modes

def test_lsblk_parses_disk_and_partitions_and_readonly_flags():
    data = (
        'NAME="sda" TYPE="disk" SIZE="107374182400" FSTYPE="" MOUNTPOINT="" RO="0"\n'
        'NAME="sda1" TYPE="part" SIZE="53687091200" FSTYPE="ext4" MOUNTPOINT="/" RO="0"\n'
        'NAME="sdb" TYPE="disk" SIZE="2147483648" FSTYPE="ext4" MOUNTPOINT="/archive" RO="1"\n'
    )
    rows = parse_block_devices(data)
    assert len(rows) == 3
    assert rows[1]["mount"] == "/"
    assert rows[2]["read_only"] is True
    assert rows[0]["size_bytes"] == 107374182400


def test_device_output_drops_invalid_names_and_sizes():
    data = ('NAME="../../etc" TYPE="disk" SIZE="50" FSTYPE="" MOUNTPOINT="" RO="0"\n'
            'NAME="sda" TYPE="disk" SIZE="-1" FSTYPE="" MOUNTPOINT="" RO="0"\n')
    assert parse_block_devices(data) == []


def test_mount_readonly_parser_does_not_guess_when_missing():
    opts = "/ rw,relatime\n/archive ro,nosuid,nodev\n"
    modes = parse_mount_modes(opts)
    assert modes["/"] is False
    assert modes["/archive"] is True
    assert "/missing" not in modes
