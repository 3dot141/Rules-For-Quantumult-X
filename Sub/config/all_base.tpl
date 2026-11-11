{% if request.target == "clash" or request.target == "clashr" %}

mixed-port: {{ default(global.clash.http_port, "7890") }}
allow-lan: {{ default(global.clash.allow_lan, "true") }}
mode: Rule
log-level: {{ default(global.clash.log_level, "info") }}
external-controller: :9090
{% if default(request.clash.dns, "1") == "1" %}
dns:
  enable: true
  ipv6: false
  listen: :1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/15
  fake-ip-filter:
    - 'geosite:private'
    - 'geosite:category-ntp'
    - 'geosite:geolocation-cn'
    - 'geosite:connectivity-check'
    - '+.lan'
    - '+.local'
    - '*.msftconnecttest.com'
    - '*.msftncsi.com'
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
  nameserver-policy:
    'geosite:cn':
      - https://dns.alidns.com/dns-query
      - 119.29.29.29
    'geosite:private': system
  proxy-server-nameserver:
    - https://doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  respect-rules: true
{% endif %}
{% if local.clash.new_field_name == "true" %}
proxies: ~
proxy-groups: ~
rules:
  # 进程规则（跨平台正则，需 TUN 模式；Windows 进程名带 .exe）
  - PROCESS-NAME-REGEX,(?i)(clash|mihomo|v2ray|xray|ss-local|sing-box)(\.exe)?,DIRECT
  - PROCESS-NAME-REGEX,(?i)(tailscale|tailscaled)(\.exe)?,DIRECT
  - PROCESS-NAME-REGEX,(?i)(wechat|weixin|wechatappex|qq|tim|wecom|wxwork|dingtalk|lark|feishu|企业微信)(\.exe)?,DIRECT
  - PROCESS-NAME-REGEX,(?i)(wemeetapp|tencentmeeting|voov)(\.exe)?,DIRECT
  - PROCESS-NAME-REGEX,(?i)(neteasemusic|cloudmusic|qqmusic)(\.exe)?,DIRECT
  - PROCESS-NAME-REGEX,(?i)(bilibili|哔哩哔哩|iqiyi|youku)(\.exe)?,DIRECT
  - PROCESS-NAME-REGEX,(?i)(baidunetdisk|adrive|quarkclouddrive|thunder|qbittorrent|aria2c|transmission|utorrent|bitcomet)(\.exe)?,DIRECT
  - PROCESS-NAME-REGEX,(?i)(wps|tencentdocs|meituan)(\.exe)?,DIRECT
  - PROCESS-NAME-REGEX,(?i)(todesk|sunloginclient)(\.exe)?,DIRECT
  # AI 应用 → AI 组（需 TUN + find-process-mode: always）
  - PROCESS-NAME-REGEX,(?i)^(cursor|claude|chatgpt|codex|grok)([ -].*)?(\.exe)?$,AI
  # npm 安装的 CLI 走 node，按安装路径兜底
  - PROCESS-PATH-REGEX,(?i)(anthropic-ai|claude-code|@openai[/\\]codex),AI
  - PROCESS-NAME,steam.exe,Games
{% else %}
Proxy: ~
Proxy Group: ~
Rule: ~
{% endif %}

{% endif %}
{% if request.target == "surge" %}

[General]
loglevel = notify
bypass-system = true
# tailscale 10.64.0.0/10 and avoid confict
skip-proxy = 127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,100.64.0.0/9,localhost,*.local,e.crashlytics.com,captive.apple.com,::ffff:0:0:0:0/1,::ffff:128:0:0:0/1
#DNS设置或根据自己网络情况进行相应设置
bypass-tun = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12
dns-server = 119.29.29.29,223.5.5.5

{% endif %}
{% if request.target == "loon" %}

[General]
skip-proxy = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,e.crashlynatics.com
bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,255.255.255.255/32
dns-server = system,119.29.29.29,223.5.5.5
allow-udp-proxy = false
host = 127.0.0.1

[Proxy]

[Remote Proxy]

[Proxy Group]

[Rule]

[Remote Rule]

[URL Rewrite]
enable = true
^https?:\/\/(www.)?(g|google)\.cn https://www.google.com 302

[Remote Rewrite]
https://raw.githubusercontent.com/Loon0x00/LoonExampleConfig/master/Rewrite/AutoRewrite_Example.list,auto

[MITM]
hostname = *.example.com,*.sample.com
enable = true
skip-server-cert-verify = true
#ca-p12 =
#ca-passphrase =

{% endif %}
{% if request.target == "quan" %}

[SERVER]

[SOURCE]

[BACKUP-SERVER]

[SUSPEND-SSID]

[POLICY]

[DNS]
1.1.1.1

[REWRITE]

[URL-REJECTION]

[TCP]

[GLOBAL]

[HOST]

[STATE]
STATE,AUTO

[MITM]

{% endif %}
{% if request.target == "quanx" %}

[general]
excluded_routes=192.168.0.0/16, 172.16.0.0/12, 100.64.0.0/10, 10.0.0.0/8
geo_location_checker=http://ip-api.com/json/?lang=zh-CN, https://github.com/KOP-XIAO/QuantumultX/raw/master/Scripts/IP_API.js
network_check_url=http://www.baidu.com/
server_check_url=http://www.gstatic.com/generate_204

[dns]
server=119.29.29.29
server=223.5.5.5
server=1.0.0.1
server=8.8.8.8

[policy]
# 2026-11 审计：删除 emoji 占位策略组（与 snippets/groups.txt 生成的组名不一致，导致 quanx 端策略列表混乱）

[server_remote]

[filter_remote]

[rewrite_remote]

[server_local]

[filter_local]

[rewrite_local]

[mitm]

{% endif %}
{% if request.target == "mellow" %}

[Endpoint]
DIRECT, builtin, freedom, domainStrategy=UseIP
REJECT, builtin, blackhole
Dns-Out, builtin, dns

[Routing]
domainStrategy = IPIfNonMatch

[Dns]
hijack = Dns-Out
clientIp = 114.114.114.114

[DnsServer]
localhost
223.5.5.5
8.8.8.8, 53, Remote
8.8.4.4

[DnsRule]
DOMAIN-KEYWORD, geosite:geolocation-!cn, Remote
DOMAIN-SUFFIX, google.com, Remote

[DnsHost]
doubleclick.net = 127.0.0.1

[Log]
loglevel = warning

{% endif %}
{% if request.target == "surfboard" %}

[General]
loglevel = notify
interface = 127.0.0.1
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local
ipv6 = false
dns-server = system, 223.5.5.5
exclude-simple-hostnames = true
enhanced-mode-by-rule = true
{% endif %}
{% if request.target == "sssub" %}
{
  "route": "bypass-lan-china",
  "remote_dns": "dns.google",
  "ipv6": false,
  "metered": false,
  "proxy_apps": {
    "enabled": false,
    "bypass": true,
    "android_list": [
      "com.eg.android.AlipayGphone",
      "com.wudaokou.hippo",
      "com.zhihu.android"
    ]
  },
  "udpdns": false
}

{% endif %}
