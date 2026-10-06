# esp32-s3-adblock

[![CI](https://github.com/EllaZhangCA/esp32-s3-adblock/actions/workflows/ci.yml/badge.svg)](https://github.com/EllaZhangCA/esp32-s3-adblock/actions/workflows/ci.yml)

ESP32-S3 局域网 DNS 广告拦截固件，基于 [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock) 的 MIT 项目（上游提交 `1947383`）移植并加固。保留 Flash 中的 40 位域名哈希、网页管理、客户端统计、自定义屏蔽和 OTA。

**默认适用于常见 N8R8（8MB Quad-SPI Flash）；不依赖 PSRAM。** 已进行六种配置的编译和主机测试；尚未完成 ESP32-S3 实板烧录、无线网络和长时间负载测试。不要把编译通过理解为所有 S3 板型均已实测。

## 选择板型

| Flash | 原生 USB 接口 | USB 转串口接口 | 两个 OTA 固件槽 | LittleFS |
| --- | --- | --- | --- | --- |
| 4MB | `s3-4mb` | `s3-4mb-uart` | 各 1.3125MiB | 1.3125MiB |
| 8MB（默认） | `s3` | `s3-uart` | 各 2MiB | 3.9375MiB |
| 16MB | `s3-16mb` | `s3-16mb-uart` | 各 2MiB | 11.9375MiB |

常见 WROOM-1/1U N4、N8、N8R2、N8R8、N16R8 的 Quad-SPI Flash 可按实际容量选择。所有配置均不启用 PSRAM，避免 Quad/Octal PSRAM 模式差异。原生 USB 使用 GPIO19/20；UART 使用板上的 CP210x/CH340 等桥接芯片。应用只额外使用 BOOT GPIO0，不驱动板载 LED。

**WROOM-2 / N16R8V / N32R8V 等 Octal Flash、32MB Flash、特殊引脚或供电板型不在已验证配置内。** 不能只按“S3”字样选固件。Flash 类型、容量和接口必须相符；PSRAM 类型不影响本项目。参考 [Espressif 板型说明](https://documentation.espressif.com/esp-dev-kits/en/latest/esp32s3/esp32-s3-devkitc-1/user_guide_v1.1.html)。

## 构建与首次刷入

安装 Python 3.12+ 和固定版本的 PlatformIO；命令在项目根目录执行：

```sh
python -m pip install platformio==6.1.19
python tools/build_blocklist.py data/blocklist.bin
python -m platformio run -e s3
python -m platformio run -e s3 -t upload
python -m platformio run -e s3 -t uploadfs
python -m platformio device monitor -b 115200
```

其他板型将上述每个 `s3` 替换为表格中的配置名。需要指定串口时，在上传命令后加 `--upload-port COM4`（示例端口，先用 `python -m platformio device list` 确认）。不要选择电脑上无关设备。

首次刷入需要同时刷固件和文件系统。`uploadfs` 会替换文件系统及其中的自定义屏蔽/封禁设置；后续更新列表请使用网页上传。WiFi 和自动生成的密码存储于独立 NVS，不包含在公开固件里。可选：将 `src/secrets.example.h` 复制为已忽略的 `src/secrets.h`，填自己的 WiFi 或 16 字符以上管理密码；不要上传该文件或含个人凭据的构建产物。

无法进入烧录模式时：按住 BOOT，点按 RESET，松开 BOOT 后重试。不要在正常启动时一直按住 BOOT，否则芯片会停留在 ROM 下载模式。

## 配网和使用

1. 打开 115200 波特率串口，读取本设备生成的管理密码和配网热点密码。终端打开太晚时输入 `?` 回车可重新显示。
2. 连接 WPA2 热点 `S3-AdBlock-XXXX`，输入串口显示的配网密码，打开 `http://192.168.4.1`，填写 **2.4GHz WiFi**。设备会保存并重启。
3. 重新连接家庭网络，访问 `http://s3adblock.local`；mDNS 不可用时使用串口或路由器显示的 IP。用户名默认 `admin`，密码见串口。
4. 在路由器为 S3 保留固定 DHCP 地址，把该地址设为客户端的 DNS。**不要同时填写公共 DNS 作为“备用 DNS”**，客户端可能直接使用它绕过过滤。若需要冗余，应配置另一台过滤 DNS。
5. 重启客户端网络或清除 DNS 缓存，然后检查：

```sh
nslookup doubleclick.net <S3的IP>
nslookup github.com <S3的IP>
```

默认列表命中的 A 查询返回 `0.0.0.0`；正常域名转发至 Quad9 `9.9.9.9:53`。AAAA 和其他被阻止类型返回无数据。自定义屏蔽在没有 Flash 列表时仍有效。标准 DNS 查询仅接受来自设备同一 IPv4 子网的客户端；跨 VLAN 应部署合适的 DNS 转发器。

更换 WiFi 可点网页的 Forget WiFi。正常启动后按住 BOOT 5 秒可清除已保存的 WiFi（GPIO0）；保持串口可读即可重新配网。

## 更新

- 网页上传 `blocklist.bin`：需要登录、POST 和防 CSRF 请求头。先写临时文件，检查长度、严格排序和写入完整性，成功后切换。失败保留旧列表，断电后可恢复备份。
- 留出旧、新两份列表及文件系统余量。4MB 版本建议单份不超过约 **640KB**；8MB/16MB 可更大。实际空间不足会拒绝更新，不会删旧列表。
- HTTPS 自动更新：仓库每周生成的地址为 `https://github.com/EllaZhangCA/esp32-s3-adblock/releases/download/blocklist/blocklist.bin`。在网页配置后启用，默认关闭。验证 TLS 证书、主机名和时间，拒绝 HTTP 降级；NTP 未同步时保留旧列表。服务器须返回 Content-Length，暂不支持 chunked 下载。默认列表超过 655KB 时，发布任务会停止，避免挤满 4MB 设备。
- 固件 OTA：在网页上传同一板型/分区配置的 `.pio/build/<配置名>/firmware.bin`。切换 Flash 容量或分区必须重新通过 USB 刷固件和文件系统。镜像格式校验不等于签名认证；只使用可信来源的固件。
- ArduinoOTA 网络服务默认关闭；需要时自行将 `ENABLE_ARDUINO_OTA=1`。网页固件 OTA 不受该开关影响。

## 安全与功能边界

本版本修复默认共享密码、开放配网 AP、配网页面 XSS、远程更新跳过证书验证、失败更新丢失旧列表、畸形 DNS 报文和大列表漏查询等问题。详情见 [SECURITY.md](SECURITY.md)，测试范围见 [docs/VALIDATION.md](docs/VALIDATION.md)。

管理网页仍为 HTTP Basic Auth，**只适用于可信局域网或隔离的管理网络**；不要映射到公网。设备没有启用 Secure Boot、Flash Encryption、签名 OTA、DNSSEC 验证或 DNS-over-TLS。固件继承 Arduino/ESP-IDF/lwIP 的依赖风险，不承诺“绝对安全”。

这是 UDP/IPv4 DNS 域名过滤器：无法屏蔽与正文同域的广告（例如许多视频内广告），不能阻止客户端自带 DoH/DoT 或 IPv6 DNS 绕过；没有 DNS TCP 回退。40 位哈希存在小概率碰撞和误拦截，较大的列表风险更高。它不替代高负载路由器级 DNS 服务。远程 HTTPS 握手、网页上传和 Flash 校验期间可能短暂增加 DNS 延迟。

## 测试和来源

```sh
python -m pip install -r requirements-dev.txt
python -m unittest discover -s test -v
# Linux/macOS:
g++ -std=c++14 -Wall -Wextra test/protocol_test.cpp -o protocol_test
./protocol_test
# Windows / Visual Studio C++ Build Tools:
powershell -ExecutionPolicy Bypass -File tools/run_host_tests.ps1
```

GitHub Actions 为六种配置构建固件和文件系统，并校验 S3 芯片 ID、真实 Flash 容量、分区边界和 OTA 空间。C++ 协议/存储测试在 Linux 使用 AddressSanitizer 与 UBSan。CI 工件只包含编译验证固件，CI 文件系统使用测试域名，不作为生产屏蔽列表发布。

MIT：保留上游 [LICENSE](LICENSE) 和作者版权。移植依据为上游提交 `19473839c27d10f666406a3ae62df97b7b155273`。默认数据来自 [StevenBlack/hosts](https://github.com/StevenBlack/hosts) 和 [Hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists)，各自许可证适用于列表。TLS 根证书来自 Mozilla/certifi，见 [certs/LICENSE](certs/LICENSE)。原 C3 二进制和外壳文件不适用于 S3，未在本仓库发布。

## English quick reference

ESP32-S3 port of M-Abozaid's MIT DNS sinkhole. Use `s3` for 8MB Quad-SPI flash (including common N8R8 modules); select 4MB/16MB and USB/UART variants from the table. PSRAM is unused. Octal-flash/WROOM-2 boards are not validated. Build, flash firmware **and** LittleFS, read the per-device passwords on serial, provision 2.4GHz WiFi, then use `s3adblock.local`. See the security and validation documents before deployment. Compilation and host tests are not a physical hardware certification.
