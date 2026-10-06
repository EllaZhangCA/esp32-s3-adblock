"""Check actual generated image headers/partitions, not just configuration text."""
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]

def check(env):
    mb = 4 if '4mb' in env else 16 if '16mb' in env else 8
    folder = ROOT/'.pio/build'/env
    parts = {}
    raw = (folder/'partitions.bin').read_bytes()
    end = 0x9000
    for i in range(0,len(raw),32):
        magic, kind, sub, offset, size, label, flags = struct.unpack('<HBBII16sI', raw[i:i+32])
        if magic != 0x50aa: break
        assert offset >= end, 'overlapping partitions'
        end = offset+size
        parts[label.rstrip(b'\0').decode()] = (offset,size)
    assert end == mb*1024*1024, f'{env}: wrong flash layout'
    fw = (folder/'firmware.bin').read_bytes()
    boot = (folder/'bootloader.bin').read_bytes()
    for image in [fw,boot]:
        assert image[0] == 0xe9 and int.from_bytes(image[12:14],'little') == 9, 'not an ESP32-S3 image'
    assert boot[3] >> 4 == {4:2,8:3,16:4}[mb], 'bootloader has wrong flash size'
    assert len(fw) <= parts['app0'][1] == parts['app1'][1], 'OTA slot overflow'
    fs = folder/'littlefs.bin'
    if fs.exists(): assert fs.stat().st_size == parts['spiffs'][1], 'filesystem has wrong size'
    print(f'{env}: S3 image, {mb}MB flash, {len(fw)}B firmware, dual OTA, LittleFS @ {parts["spiffs"][0]:#x}: OK')

if __name__ == '__main__':
    for env in sys.argv[1:] or ['s3']: check(env)
