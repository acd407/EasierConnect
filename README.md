# EasierConnect

一款开源的深信服EasyConnect VPN客户端实现，采用Go语言编写。

## 功能特性

- 跨平台支持（Windows、Linux、macOS）
- 支持通过SOCKS5代理转发流量
- 支持短信和TOTP双因素身份验证
- 彩色终端输出，可通过 `--no-color` 选项禁用
- 基于gVisor用户态网络栈实现TUN设备
- 支持自动获取IP地址并通过虚拟网卡访问内网资源

## 安装

### 从源码构建

```bash
git clone https://github.com/your-repo/EasierConnect.git
cd EasierConnect
go mod tidy
go build .
```

### 使用

```bash
./EasierConnect --server vpn.example.com --username user --password pass
```

### 命令行参数

| 参数 | 描述 |
|------|-------------|
| `--server` | EasyConnect服务器地址 |
| `--username` | 用户名 |
| `--password` | 密码 |
| `--port` | EasyConnect服务器端口（默认: 443） |
| `--socks-bind` | SOCKS5服务监听地址（默认: `:1080`） |
| `--totp-key` | TOTP密钥，用于自动生成双因子认证码 |
| `--twf-id` | 使用捕获的TWFID登录（主要用于调试） |
| `--debug-dump` | 启用流量调试转储（仅用于调试） |
| `--no-color` | 禁用彩色输出 |

### 双因素认证支持

本项目支持多种双因素认证方式：

1. **短信验证码**: 登录过程中会提示输入短信验证码
2. **TOTP认证**: 可提供TOTP密钥自动计算验证码，或手动输入

## 技术架构

- **网络栈**: 基于gVisor用户态网络栈实现，提供完整的TCP/IP协议栈
- **协议实现**: 深度解析和实现了深信服EasyConnect协议
- **代理服务**: 内置SOCKS5代理服务器，便于应用程序连接
- **认证流程**: 完整实现Web登录、TWFID获取、二步验证等流程

## 使用场景

- 访问企业内网资源
- 安全远程办公
- 绕过网络限制
- 学校、企业VPN接入

## 注意事项

- 请确保您有权限访问目标VPN服务器
- 遵守相关网络使用政策和法律法规
- 项目仅供学习和技术研究使用

## 贡献

欢迎提交Issue和Pull Request来改进项目。

## 替代方案

- [docker-easyconnect](https://github.com/Hagb/docker-easyconnect) - 在Docker容器中运行EasyConnect