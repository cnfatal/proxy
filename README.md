# Linux Transparent Proxy with Clash Rules

一个 Linux 透明代理程序，支持 HTTP/HTTPS 流量透明代理，使用 Clash 兼容规则进行流量过滤。

## 功能特性

- ✅ 透明代理 80/443 端口流量
- ✅ 支持 HTTP 和 SOCKS5 上游代理
- ✅ Clash 兼容规则格式
- ✅ 使用 nftables (netlink) 管理规则，无需调用外部命令
- ✅ systemd 服务支持
- ✅ 自动设置和清理防火墙规则

## 支持的规则类型

| 规则类型         | 说明             | 示例                             |
| ---------------- | ---------------- | -------------------------------- |
| `DOMAIN`         | 精确域名匹配     | `DOMAIN,www.google.com,PROXY`    |
| `DOMAIN-SUFFIX`  | 域名后缀匹配     | `DOMAIN-SUFFIX,google.com,PROXY` |
| `DOMAIN-KEYWORD` | 域名关键字匹配   | `DOMAIN-KEYWORD,youtube,PROXY`   |
| `IP-CIDR`        | IPv4 CIDR 匹配   | `IP-CIDR,192.168.0.0/16,DIRECT`  |
| `IP-CIDR6`       | IPv6 CIDR 匹配   | `IP-CIDR6,::1/128,DIRECT`        |
| `MATCH`          | 默认规则（兜底） | `MATCH,DIRECT`                   |

## 支持的策略

| 策略     | 说明             |
| -------- | ---------------- |
| `PROXY`  | 通过上游代理转发 |
| `DIRECT` | 直接连接目标     |
| `REJECT` | 拒绝连接         |

## 安装

### 编译

```bash
make build
```

### 安装到系统

```bash
# 安装二进制和配置文件
sudo make install

# 编辑配置文件
sudo vim /etc/tproxy/config.yaml

# 安装并启用 systemd 服务
sudo make systemd-install
sudo systemctl enable --now tproxy
```

### 卸载

```bash
# 卸载 systemd 服务和二进制
sudo make uninstall
```

### Makefile 目标

| 目标                     | 说明                 |
| ------------------------ | -------------------- |
| `make build`             | 编译二进制文件       |
| `make install`           | 安装二进制和配置文件 |
| `make systemd-install`   | 安装为 systemd 服务  |
| `make systemd-uninstall` | 卸载 systemd 服务    |
| `make uninstall`         | 完全卸载             |
| `make clean`             | 清理构建产物         |
| `make run`               | 本地运行（开发用）   |

## 配置

编辑配置文件 `/etc/tproxy/config.yaml`：

```yaml
# 代理监听地址
listen: ":12345"

# 上游代理地址，支持 http:// 或 socks5://
upstream: "http://proxy.example.com:8080"
# 或: upstream: "socks5://proxy.example.com:1080"

# Clash 兼容规则
rules:
  # 直连规则
  - IP-CIDR,127.0.0.0/8,DIRECT
  - IP-CIDR,192.168.0.0/16,DIRECT
  - DOMAIN-SUFFIX,cn,DIRECT

  # 代理规则
  - DOMAIN-SUFFIX,google.com,PROXY
  - DOMAIN-SUFFIX,github.com,PROXY

  # 默认规则
  - MATCH,DIRECT
```

## 使用方法

### 直接运行

```bash
# 需要 root 权限
sudo ./tproxy -config config.yaml
```

### 命令行参数

| 参数       | 说明                                |
| ---------- | ----------------------------------- |
| `-config`  | 配置文件路径（默认: `config.yaml`） |
| `-setup`   | 仅设置 nftables 规则后退出          |
| `-cleanup` | 仅清理 nftables 规则后退出          |

### systemd 服务

```bash
# 复制服务文件
sudo cp tproxy.service /etc/systemd/system/

# 重新加载 systemd
sudo systemctl daemon-reload

# 启动服务
sudo systemctl start tproxy

# 设置开机启动
sudo systemctl enable tproxy

# 查看状态
sudo systemctl status tproxy

# 查看日志
sudo journalctl -u tproxy -f
```

## 工作原理

1. 程序启动时，通过 nftables (netlink API) 创建 NAT 规则，将本机发出的 80/443 端口流量重定向到代理监听端口
2. 代理接收连接后，使用 `SO_ORIGINAL_DST` 获取原始目标地址
3. 根据 Clash 规则匹配目标地址，决定策略（PROXY/DIRECT/REJECT）
4. PROXY 策略：通过上游代理（HTTP CONNECT 或 SOCKS5）转发
5. DIRECT 策略：直接连接目标
6. REJECT 策略：关闭连接
7. 程序退出时自动清理 nftables 规则

## 注意事项

1. **需要 root 权限**：程序需要 root 权限来管理 nftables 规则
2. **nftables 支持**：需要 Linux 内核支持 nftables (Linux 3.13+)
3. **仅代理本机流量**：当前实现仅代理本机发出的流量，不代理转发流量

## 许可证

MIT License
