# Link42 UDPspeeder assets

`assets/udpspeeder-x64-static` 和 `assets/udpspeeder-arm64-musl` 是由 UDPspeeder
`wangyu-/UDPspeeder` 仓库构建的静态测试/发布资产，来源提交为
`b6a1b5941d9ebb6ef4f6866abdf1e03a47b99b2d`。

发布前应在构建环境重新编译并核对架构、`--help` 自检和 SHA-256。当前资产用于 Linux x86_64
和 OpenWrt aarch64；其它架构在 Agent 中会明确返回不支持，不会误下载其它架构的文件。
