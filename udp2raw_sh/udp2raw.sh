#!/bin/sh
set -eu

BASE_URL="${UDP2RAW_BASE_URL:-https://get.pmman.tech/sh}"
BIN_DIR_URL="${UDP2RAW_BIN_DIR_URL:-$BASE_URL/udp2raw_bin}"
INSTALL_BIN="/usr/local/bin/udp2raw"
LIBEXEC_DIR="/usr/local/libexec"
CONFIG_DIR="/etc/udp2raw"
SYSTEMD_DIR="/etc/systemd/system"
OPENWRT_INIT="/etc/init.d/udp2raw"

die() {
    echo "错误：$*" >&2
    exit 1
}

info() {
    echo "==> $*"
}

need_root() {
    [ "$(id -u)" -eq 0 ] || die "请使用 root 用户运行"
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

download() {
    url="$1"
    output="$2"

    case "$url" in
        file://*)
            cp "${url#file://}" "$output"
            ;;
        *)
            if have_cmd curl; then
        curl -fsSL "$url" -o "$output"
            elif have_cmd wget; then
        wget -qO "$output" "$url"
            else
        die "需要安装 curl 或 wget"
            fi
            ;;
    esac
}

copy_executable() {
    src="$1"
    dst="$2"
    dst_dir="${dst%/*}"

    mkdir -p "$dst_dir"
    cp "$src" "$dst"
    chmod 0755 "$dst"
}

cpu_has_aes() {
    [ -r /proc/cpuinfo ] && grep -qi ' aes ' /proc/cpuinfo
}

machine_endian() {
    if have_cmd lscpu && lscpu 2>/dev/null | grep -qi 'little endian'; then
        echo le
        return
    fi

    case "$(printf '\1' | od -An -tx1 2>/dev/null | tr -d ' ')" in
        01) echo le ;;
        *) echo be ;;
    esac
}

detect_udp2raw_bin() {
    if [ -n "${UDP2RAW_BIN:-}" ]; then
        echo "$UDP2RAW_BIN"
        return
    fi

    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)
            if cpu_has_aes; then echo udp2raw_amd64_hw_aes; else echo udp2raw_amd64; fi
            ;;
        i386|i486|i586|i686)
            if cpu_has_aes; then echo udp2raw_x86_asm_aes; else echo udp2raw_x86; fi
            ;;
        armv5*|armv6*|armv7*|armhf|arm)
            echo udp2raw_arm
            ;;
        aarch64|arm64)
            echo udp2raw_arm
            ;;
        mips*|MIPS*)
            endian="$(machine_endian)"
            if [ "$endian" = le ]; then echo udp2raw_mips24kc_le; else echo udp2raw_mips24kc_be; fi
            ;;
        *)
            die "暂不支持架构 '$arch'，请手动指定 UDP2RAW_BIN，例如 UDP2RAW_BIN=udp2raw_amd64"
            ;;
    esac
}

is_openwrt() {
    [ -r /etc/openwrt_release ] || { [ -x /sbin/procd ] && [ -x /etc/rc.common ]; }
}

service_backend() {
    if is_openwrt; then
        echo openwrt
    elif have_cmd systemctl; then
        echo systemd
    else
        echo none
    fi
}

install_udp2raw_bin() {
    bin_name="$(detect_udp2raw_bin)"
    tmp_file="$(mktemp)"
    trap 'rm -f "$tmp_file"' EXIT INT TERM

    info "下载 $bin_name"
    download "$BIN_DIR_URL/$bin_name" "$tmp_file"

    info "覆盖安装 $INSTALL_BIN"
    copy_executable "$tmp_file" "$INSTALL_BIN"
}

install_wrapper() {
    info "覆盖安装 $LIBEXEC_DIR/udp2raw-systemd"
    mkdir -p "$LIBEXEC_DIR"
    cat > "$LIBEXEC_DIR/udp2raw-systemd" <<'EOF'
#!/bin/sh
set -eu

usage() {
    echo "用法：$0 server|client 实例名" >&2
    exit 2
}

[ "$#" -eq 2 ] || usage

mode="$1"
instance="$2"

case "$mode" in
    server|client) ;;
    *) usage ;;
esac

config="/etc/udp2raw/$mode"

if [ ! -r "$config" ]; then
    echo "udp2raw：配置文件不存在或不可读：$config" >&2
    exit 1
fi

line=$(
    awk -v name="$instance" '
        /^[[:space:]]*($|#)/ { next }
        {
            key = $1
            sub(/=$/, "", key)
            if (key == name) {
                sub(/^[[:space:]]*[^[:space:]=]+[[:space:]]*=?[[:space:]]*/, "")
                print
                found = 1
                exit
            }
        }
        END {
            if (!found) exit 1
        }
    ' "$config"
) || {
    echo "udp2raw：实例 '$instance' 不存在于 $config" >&2
    exit 1
}

if [ -z "$line" ]; then
    echo "udp2raw：实例 '$instance' 的参数为空" >&2
    exit 1
fi

eval "set -- $line"
exec /usr/local/bin/udp2raw "$@"
EOF
    chmod 0755 "$LIBEXEC_DIR/udp2raw-systemd"
}

install_units() {
    info "覆盖安装 systemd 模板服务"
    mkdir -p "$SYSTEMD_DIR"

    cat > "$SYSTEMD_DIR/udp2raw-server@.service" <<'EOF'
[Unit]
Description=udp2raw server instance %i
Documentation=https://github.com/wangyu-/udp2raw
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/libexec/udp2raw-systemd server %i
User=root
Group=root
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    cat > "$SYSTEMD_DIR/udp2raw-client@.service" <<'EOF'
[Unit]
Description=udp2raw client instance %i
Documentation=https://github.com/wangyu-/udp2raw
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/libexec/udp2raw-systemd client %i
User=root
Group=root
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
}

install_openwrt_init() {
    info "覆盖安装 OpenWrt init 脚本 $OPENWRT_INIT"
    cat > "$OPENWRT_INIT" <<'EOF'
#!/bin/sh /etc/rc.common

START=99
STOP=10

BIN="/usr/local/bin/udp2raw"
CONFIG_DIR="/etc/udp2raw"
PID_DIR="/var/run/udp2raw"

EXTRA_COMMANDS="start_instance stop_instance restart_instance status_instance"
EXTRA_HELP="        start_instance <server|client> <name>   Start one udp2raw rule
        stop_instance <server|client> <name>    Stop one udp2raw rule
        restart_instance <server|client> <name> Restart one udp2raw rule
        status_instance <server|client> <name>  Show one udp2raw rule status"

get_args() {
    mode="$1"
    name="$2"
    config="$CONFIG_DIR/$mode"

    [ -r "$config" ] || return 1
    awk -v name="$name" '
        /^[[:space:]]*($|#)/ { next }
        {
            key = $1
            sub(/=$/, "", key)
            if (key == name) {
                sub(/^[[:space:]]*[^[:space:]=]+[[:space:]]*=?[[:space:]]*/, "")
                print
                found = 1
                exit
            }
        }
        END {
            if (!found) exit 1
        }
    ' "$config"
}

pid_file() {
    echo "$PID_DIR/udp2raw-$1-$2.pid"
}

start_one() {
    mode="$1"
    name="$2"
    args="$(get_args "$mode" "$name")" || {
        echo "udp2raw: rule not found: $mode/$name" >&2
        return 1
    }

    [ -x "$BIN" ] || {
        echo "udp2raw: binary not executable: $BIN" >&2
        return 1
    }

    mkdir -p "$PID_DIR"
    pid="$(pid_file "$mode" "$name")"
    eval "set -- $args"
    start-stop-daemon -S -q -b -m -p "$pid" -x "$BIN" -- "$@"
}

stop_one() {
    mode="$1"
    name="$2"
    pid="$(pid_file "$mode" "$name")"
    [ -e "$pid" ] || return 0
    start-stop-daemon -K -q -p "$pid" || true
    rm -f "$pid"
}

status_one() {
    mode="$1"
    name="$2"
    pid="$(pid_file "$mode" "$name")"
    if [ -s "$pid" ] && kill -0 "$(cat "$pid")" 2>/dev/null; then
        echo "running: udp2raw-$mode@$name pid $(cat "$pid")"
    else
        echo "stopped: udp2raw-$mode@$name"
        return 1
    fi
}

each_rule() {
    mode="$1"
    config="$CONFIG_DIR/$mode"
    [ -r "$config" ] || return 0
    awk '
        /^[[:space:]]*($|#)/ { next }
        {
            key = $1
            sub(/=$/, "", key)
            print key
        }
    ' "$config"
}

start_service() {
    for mode in server client; do
        for name in $(each_rule "$mode"); do
            start_one "$mode" "$name"
        done
    done
}

stop_service() {
    for mode in client server; do
        for name in $(each_rule "$mode"); do
            stop_one "$mode" "$name"
        done
    done
}

start_instance() {
    [ "$#" -eq 2 ] || {
        echo "usage: $0 start_instance <server|client> <name>" >&2
        return 2
    }
    start_one "$1" "$2"
}

stop_instance() {
    [ "$#" -eq 2 ] || {
        echo "usage: $0 stop_instance <server|client> <name>" >&2
        return 2
    }
    stop_one "$1" "$2"
}

restart_instance() {
    [ "$#" -eq 2 ] || {
        echo "usage: $0 restart_instance <server|client> <name>" >&2
        return 2
    }
    stop_one "$1" "$2"
    start_one "$1" "$2"
}

status_instance() {
    [ "$#" -eq 2 ] || {
        echo "usage: $0 status_instance <server|client> <name>" >&2
        return 2
    }
    status_one "$1" "$2"
}
EOF
    chmod 0755 "$OPENWRT_INIT"
}

init_configs() {
    info "初始化 $CONFIG_DIR"
    mkdir -p "$CONFIG_DIR"
    chmod 0755 "$CONFIG_DIR"

    refresh_config_file server
    refresh_config_file client
}

refresh_config_file() {
    mode="$1"
    file="$CONFIG_DIR/$mode"
    tmp="$(mktemp)"

    if [ "$mode" = server ]; then
        cat > "$tmp" <<'EOF'
# 格式：
# 名称 udp2raw参数...
#
# 示例：
# homelab -s -l0.0.0.0:23002 -r127.0.0.1:12312 -k 'change-me' --raw-mode faketcp --cipher-mode xor -a
EOF
    else
        cat > "$tmp" <<'EOF'
# 格式：
# 名称 udp2raw参数...
#
# 示例：
# homelab -c -l127.0.0.1:12312 -rSERVER_IP:23002 -k 'change-me' --raw-mode faketcp --cipher-mode xor -a
EOF
    fi

    if [ -e "$file" ]; then
        awk 'NF && $1 !~ /^#/' "$file" >> "$tmp"
    fi

    cat "$tmp" > "$file"
    rm -f "$tmp"
    chmod 0644 "$file"
}

reload_systemd() {
    if [ "$(service_backend)" = openwrt ]; then
        return
    elif have_cmd systemctl; then
        info "重新加载 systemd"
        systemctl daemon-reload
    else
        info "未找到 systemctl，跳过 daemon-reload"
    fi
}

managed_service_installed() {
    case "$(service_backend)" in
        openwrt) [ -x "$OPENWRT_INIT" ] ;;
        systemd) [ -x "$LIBEXEC_DIR/udp2raw-systemd" ] && [ -e "$SYSTEMD_DIR/udp2raw-server@.service" ] && [ -e "$SYSTEMD_DIR/udp2raw-client@.service" ] ;;
        *) return 1 ;;
    esac
}

install_all() {
    need_root
    install_udp2raw_bin
    case "$(service_backend)" in
        openwrt)
            install_openwrt_init
            ;;
        systemd)
            install_wrapper
            install_units
            ;;
        *)
            die "未检测到支持的服务管理器：需要 systemd 或 OpenWrt procd/rc.common"
            ;;
    esac
    init_configs
    install_menu_command
    reload_systemd
}

print_next_steps() {
    cat <<EOF

安装完成。

进入管理菜单：
  udp2raw-menu
  sh $0 menu

配置文件位置：
  $CONFIG_DIR/server
  $CONFIG_DIR/client
EOF
}

pause() {
    printf '\n按 Enter 返回菜单... '
    read _ans || true
}

clear_screen() {
    if have_cmd clear; then clear >/dev/null 2>&1 || true; fi
}

ensure_installed_for_menu() {
    init_configs >/dev/null
    if ! managed_service_installed; then
        echo "udp2raw 服务文件尚未安装。"
        printf "现在安装/覆盖安装？[Y/n]: "
        read ans || ans=y
        case "$ans" in
            n|N) return ;;
            *) install_all ;;
        esac
    fi
}

mode_file() {
    case "$1" in
        server|client) echo "$CONFIG_DIR/$1" ;;
        *) return 1 ;;
    esac
}

unit_name() {
    mode="$1"
    name="$2"
    printf 'udp2raw-%s@%s' "$mode" "$name"
}

valid_name() {
    case "$1" in
        ''|*[!A-Za-z0-9_.:-]*)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

valid_port() {
    case "$1" in
        ''|*[!0-9]*)
            return 1
            ;;
    esac
    [ "$1" -ge 1 ] 2>/dev/null && [ "$1" -le 65535 ] 2>/dev/null
}

shell_quote() {
    printf "'%s'" "$(printf "%s" "$1" | sed "s/'/'\\\\''/g")"
}

prompt_required() {
    text="$1"
    value=""
    while [ -z "$value" ]; do
        printf "%s: " "$text" >&2
        read value
    done
    echo "$value"
}

prompt_default() {
    text="$1"
    default="$2"
    printf "%s [%s]: " "$text" "$default" >&2
    read value || value=""
    if [ -z "$value" ]; then
        echo "$default"
    else
        echo "$value"
    fi
}

prompt_port() {
    text="$1"
    default="${2:-}"
    while :; do
        if [ -n "$default" ]; then
            value="$(prompt_default "$text" "$default")"
        else
            value="$(prompt_required "$text")"
        fi
        if valid_port "$value"; then
            echo "$value"
            return
        fi
        echo "端口必须是 1-65535 的数字。" >&2
    done
}

read_mode() {
    printf "类型：1) server  2) client [1/2]: " >&2
    read mode
    case "$mode" in
        1|s|server|服务端) echo server ;;
        2|c|client|客户端) echo client ;;
        *) echo "类型无效" >&2; return 1 ;;
    esac
}

rule_exists() {
    mode="$1"
    name="$2"
    file="$(mode_file "$mode")"
    awk -v name="$name" '
        /^[[:space:]]*($|#)/ { next }
        {
            key = $1
            sub(/=$/, "", key)
            if (key == name) found = 1
        }
        END { exit found ? 0 : 1 }
    ' "$file"
}

get_rule_args() {
    mode="$1"
    name="$2"
    file="$(mode_file "$mode")"
    awk -v name="$name" '
        /^[[:space:]]*($|#)/ { next }
        {
            key = $1
            sub(/=$/, "", key)
            if (key == name) {
                sub(/^[[:space:]]*[^[:space:]=]+[[:space:]]*=?[[:space:]]*/, "")
                print
                exit
            }
        }
    ' "$file"
}

set_rule() {
    mode="$1"
    name="$2"
    args="$3"
    file="$(mode_file "$mode")"
    tmp="$(mktemp)"

    awk -v name="$name" -v args="$args" '
        BEGIN { written = 0 }
        /^[[:space:]]*($|#)/ { print; next }
        {
            key = $1
            sub(/=$/, "", key)
            if (key == name) {
                print name " " args
                written = 1
            } else {
                print
            }
        }
        END {
            if (!written) print name " " args
        }
    ' "$file" > "$tmp"
    cat "$tmp" > "$file"
    rm -f "$tmp"
}

delete_rule_line() {
    mode="$1"
    name="$2"
    file="$(mode_file "$mode")"
    tmp="$(mktemp)"

    awk -v name="$name" '
        /^[[:space:]]*($|#)/ { print; next }
        {
            key = $1
            sub(/=$/, "", key)
            if (key != name) print
        }
    ' "$file" > "$tmp"
    cat "$tmp" > "$file"
    rm -f "$tmp"
}

other_rules_exist() {
    deleting_mode="$1"
    deleting_name="$2"
    for other_mode in server client; do
        other_file="$(mode_file "$other_mode")"
        awk -v candidate_mode="$other_mode" -v deleting_mode="$deleting_mode" -v deleting_name="$deleting_name" '
            /^[[:space:]]*($|#)/ { next }
            {
                key = $1
                sub(/=$/, "", key)
                if (!(candidate_mode == deleting_mode && key == deleting_name)) found = 1
            }
            END { exit found ? 0 : 1 }
        ' "$other_file" && return 0
    done
    return 1
}

disable_deleted_rule_autostart() {
    mode="$1"
    name="$2"
    case "$(service_backend)" in
        openwrt)
            if other_rules_exist "$mode" "$name"; then
                echo "仍有其他规则，保留 OpenWrt 开机自启。"
            else
                echo "没有其他规则，取消开机自启..."
                service_action_for "$mode" "$name" disable || true
            fi
            ;;
        *)
            echo "取消开机自启..."
            service_action_for "$mode" "$name" disable || true
            ;;
    esac
}

list_rules() {
    clear_screen
    echo "udp2raw 规则列表"
    echo
    for mode in server client; do
        file="$(mode_file "$mode")"
        if [ "$mode" = server ]; then title="服务端"; else title="客户端"; fi
        echo "[$title] $file"
        awk '
            /^[[:space:]]*($|#)/ { next }
            {
                key = $1
                sub(/=$/, "", key)
                sub(/^[[:space:]]*[^[:space:]=]+[[:space:]]*=?[[:space:]]*/, "")
                printf "  %-20s %s\n", key, $0
            }
        ' "$file"
        echo
    done
}

write_rule_index() {
    index_output="$1"
    index_source_tmp="$(mktemp)"
    : > "$index_source_tmp"

    for mode in server client; do
        file="$(mode_file "$mode")"
        awk -v mode="$mode" '
            /^[[:space:]]*($|#)/ { next }
            {
                key = $1
                sub(/=$/, "", key)
                sub(/^[[:space:]]*[^[:space:]=]+[[:space:]]*=?[[:space:]]*/, "")
                print mode "\t" key "\t" $0
            }
        ' "$file" >> "$index_source_tmp"
    done

    awk -F '\t' '{ print NR "\t" $0 }' "$index_source_tmp" > "$index_output"
    rm -f "$index_source_tmp"
}

select_rule() {
    select_index_tmp="$(mktemp)"
    write_rule_index "$select_index_tmp"

    if [ ! -s "$select_index_tmp" ]; then
        rm -f "$select_index_tmp"
        echo "当前没有规则，请先创建规则。" >&2
        return 1
    fi

    echo "请选择要管理的规则：" >&2
    awk -F '\t' '
        {
            title = ($2 == "server") ? "服务端" : "客户端"
            printf "  %2d) %-6s %-20s %s\n", $1, title, $3, $4
        }
    ' "$select_index_tmp" >&2
    printf "输入编号（直接回车取消）: " >&2
    read choice || {
        rm -f "$select_index_tmp"
        return 1
    }

    case "$choice" in
        '') rm -f "$select_index_tmp"; echo "已取消。" >&2; return 1 ;;
        *[!0-9]*)
            rm -f "$select_index_tmp"
            echo "编号无效。" >&2
            return 1
            ;;
    esac

    selected="$(awk -F '\t' -v choice="$choice" '$1 == choice { print $2 " " $3; found = 1 } END { exit found ? 0 : 1 }' "$select_index_tmp")" || {
        rm -f "$select_index_tmp"
        echo "编号不存在。" >&2
        return 1
    }
    rm -f "$select_index_tmp"
    echo "$selected"
}

enable_and_start_rule() {
    mode="$1"
    name="$2"

    echo "设置开机自启..."
    service_action_for "$mode" "$name" enable || return 1

    if rule_is_active "$mode" "$name"; then
        echo "规则已在运行，正在重启使配置生效..."
        restart_rule_service "$mode" "$name"
    else
        echo "正在启动规则..."
        service_action_for "$mode" "$name" start
    fi
}

build_server_args() {
    listen_port="$(prompt_port "监听 TCP 端口")"
    target_host="$(prompt_default "目标 UDP 地址" "127.0.0.1")"
    target_port="$(prompt_port "目标 UDP 端口")"
    key="$(prompt_required "密码/密钥")"
    raw_mode="$(prompt_default "raw-mode" "faketcp")"
    cipher_mode="$(prompt_default "cipher-mode" "xor")"
    printf "自动添加 iptables 规则 -a？[Y/n]: " >&2
    read auto_rule || auto_rule=y

    args="-s -l0.0.0.0:$listen_port -r$target_host:$target_port -k $(shell_quote "$key") --raw-mode $raw_mode --cipher-mode $cipher_mode"
    case "$auto_rule" in
        n|N) ;;
        *) args="$args -a" ;;
    esac
    echo "$args"
}

build_client_args() {
    local_port="$(prompt_port "本地 UDP 端口")"
    remote_host="$(prompt_required "远程 server 地址")"
    remote_port="$(prompt_port "远程 server TCP 端口")"
    key="$(prompt_required "密码/密钥")"
    raw_mode="$(prompt_default "raw-mode" "faketcp")"
    cipher_mode="$(prompt_default "cipher-mode" "xor")"
    printf "自动添加 iptables 规则 -a？[Y/n]: " >&2
    read auto_rule || auto_rule=y

    args="-c -l127.0.0.1:$local_port -r$remote_host:$remote_port -k $(shell_quote "$key") --raw-mode $raw_mode --cipher-mode $cipher_mode"
    case "$auto_rule" in
        n|N) ;;
        *) args="$args -a" ;;
    esac
    echo "$args"
}

add_or_edit_rule() {
    mode="$(read_mode)" || return
    printf "规则名称（例如 homelab）: "
    read name
    valid_name "$name" || {
        echo "名称无效。只能使用字母、数字、点、下划线、冒号或横线。"
        return
    }

    if rule_exists "$mode" "$name"; then
        old_args="$(get_rule_args "$mode" "$name")"
        echo "当前规则："
        echo "  $name $old_args"
        printf "覆盖这条规则？[Y/n]: "
        read ans || ans=y
        case "$ans" in
            n|N) echo "已取消。"; return ;;
        esac
    fi

    echo
    if [ "$mode" = server ]; then
        echo "创建服务端规则：对外监听 TCP，转发到本机/内网 UDP 服务。"
        args="$(build_server_args)"
    else
        echo "创建客户端规则：本地监听 UDP，连接远程 udp2raw server。"
        args="$(build_client_args)"
    fi

    set_rule "$mode" "$name" "$args"
    echo
    echo "已保存：$name $args"
    enable_and_start_rule "$mode" "$name"
}

add_raw_rule() {
    mode="$(read_mode)" || return
    printf "规则名称: "
    read name
    valid_name "$name" || {
        echo "名称无效。"
        return
    }
    printf "完整 udp2raw 参数（不含规则名称）: "
    read args
    [ -n "$args" ] || {
        echo "参数为空，已取消。"
        return
    }
    set_rule "$mode" "$name" "$args"
    echo "已保存：$name $args"
    enable_and_start_rule "$mode" "$name"
}

delete_rule() {
    selection="$(select_rule)" || return
    set -- $selection
    mode="$1"
    name="$2"

    unit="$(unit_name "$mode" "$name")"
    if rule_is_active "$mode" "$name"; then
        printf "$unit 正在运行。删除前停止它？[Y/n]: "
        read ans || ans=y
        case "$ans" in
            n|N) echo "已取消。"; return ;;
            *) service_action_for "$mode" "$name" stop ;;
        esac
    fi

    printf "确认删除 $mode 规则 '$name'？[y/N]: "
    read confirm || confirm=n
    case "$confirm" in
        y|Y)
            disable_deleted_rule_autostart "$mode" "$name"
            delete_rule_line "$mode" "$name"
            echo "已删除。"
            ;;
        *) echo "已取消。" ;;
    esac
}

show_status() {
    mode="$1"
    name="$2"
    unit="$(unit_name "$mode" "$name")"
    case "$(service_backend)" in
        openwrt)
            "$OPENWRT_INIT" status_instance "$mode" "$name" || true
            ;;
        systemd)
            systemctl status "$unit" --no-pager || true
            ;;
        *)
            echo "未检测到支持的服务管理器"
            ;;
    esac
}

rule_is_active() {
    mode="$1"
    name="$2"
    case "$(service_backend)" in
        openwrt) "$OPENWRT_INIT" status_instance "$mode" "$name" >/dev/null 2>&1 ;;
        systemd) systemctl is-active --quiet "$(unit_name "$mode" "$name")" ;;
        *) return 1 ;;
    esac
}

restart_rule_service() {
    mode="$1"
    name="$2"
    case "$(service_backend)" in
        openwrt) "$OPENWRT_INIT" restart_instance "$mode" "$name" ;;
        systemd) systemctl restart "$(unit_name "$mode" "$name")" ;;
        *) echo "未检测到支持的服务管理器"; return 1 ;;
    esac
}

service_action() {
    action="$1"
    selection="$(select_rule)" || return
    set -- $selection
    mode="$1"
    name="$2"

    service_action_for "$mode" "$name" "$action"
}

service_action_for() {
    mode="$1"
    name="$2"
    action="$3"
    unit="$(unit_name "$mode" "$name")"

    case "$action" in
        start)
            case "$(service_backend)" in
                openwrt) "$OPENWRT_INIT" start_instance "$mode" "$name" ;;
                systemd) systemctl start "$unit" ;;
                *) echo "未检测到支持的服务管理器"; return 1 ;;
            esac
            ;;
        stop)
            case "$(service_backend)" in
                openwrt) "$OPENWRT_INIT" stop_instance "$mode" "$name" ;;
                systemd) systemctl stop "$unit" ;;
                *) echo "未检测到支持的服务管理器"; return 1 ;;
            esac
            ;;
        restart)
            restart_rule_service "$mode" "$name"
            ;;
        enable)
            case "$(service_backend)" in
                openwrt) "$OPENWRT_INIT" enable ;;
                systemd) systemctl enable "$unit" ;;
                *) echo "未检测到支持的服务管理器"; return 1 ;;
            esac
            ;;
        disable)
            case "$(service_backend)" in
                openwrt) "$OPENWRT_INIT" disable ;;
                systemd) systemctl disable "$unit" ;;
                *) echo "未检测到支持的服务管理器"; return 1 ;;
            esac
            ;;
        status) show_status "$mode" "$name" ;;
        logs)
            case "$(service_backend)" in
                openwrt)
                    if have_cmd logread; then
                        logread | grep -i udp2raw | tail -n 80 || true
                    else
                        echo "未找到 logread"
                    fi
                    ;;
                systemd)
                    journalctl -u "$unit" -n 80 --no-pager || true
                    ;;
                *)
                    echo "未检测到支持的服务管理器"
                    ;;
            esac
            ;;
    esac
}

edit_raw_file() {
    mode="$(read_mode)" || return
    file="$(mode_file "$mode")"
    editor="${EDITOR:-}"
    if [ -z "$editor" ]; then
        if have_cmd nano; then editor=nano
        elif have_cmd vi; then editor=vi
        else die "未找到编辑器，请设置 EDITOR=/path/to/editor"
        fi
    fi
    "$editor" "$file"
}

install_menu_command() {
    target="/usr/local/bin/udp2raw-menu"
    info "覆盖安装 $target"
    if [ -r "$0" ]; then
        copy_executable "$0" "$target"
        return
    fi

    mkdir -p "${target%/*}"
    cat > "$target" <<EOF
#!/bin/sh
BASE_URL="\${UDP2RAW_BASE_URL:-$BASE_URL}"
SCRIPT_URL="\${UDP2RAW_SCRIPT_URL:-\$BASE_URL/udp2raw.sh}"

if command -v curl >/dev/null 2>&1; then
    exec sh -c "url=\\\$1; shift; curl -fsSL \"\\\$url\" | sh -s -- menu \"\\\$@\"" sh "\$SCRIPT_URL" "\$@"
elif command -v wget >/dev/null 2>&1; then
    exec sh -c "url=\\\$1; shift; wget -qO- \"\\\$url\" | sh -s -- menu \"\\\$@\"" sh "\$SCRIPT_URL" "\$@"
else
    echo "错误：需要安装 curl 或 wget" >&2
    exit 1
fi
EOF
    chmod 0755 "$target"
}

menu() {
    need_root
    if [ ! -t 0 ] && ( : </dev/tty ) 2>/dev/null; then
        exec </dev/tty
    fi
    ensure_installed_for_menu

    while :; do
        clear_screen
        cat <<EOF
udp2raw 管理菜单

1) 覆盖安装/更新 udp2raw 和服务文件
2) 查看规则
3) 向导式创建/覆盖规则
4) 删除规则
5) 启动规则
6) 停止规则
7) 重启规则
8) 查看服务状态
9) 设置开机自启
10) 取消开机自启
11) 查看日志
12) 编辑原始配置文件
13) 高级：直接填写完整参数
0) 退出

EOF
        printf "请选择: "
        read choice || exit 0
        case "$choice" in
            1) install_all; print_next_steps; pause ;;
            2) list_rules; pause ;;
            3) add_or_edit_rule; pause ;;
            4) delete_rule; pause ;;
            5) service_action start; pause ;;
            6) service_action stop; pause ;;
            7) service_action restart; pause ;;
            8) service_action status; pause ;;
            9) service_action enable; pause ;;
            10) service_action disable; pause ;;
            11) service_action logs; pause ;;
            12) edit_raw_file; pause ;;
            13) add_raw_rule; pause ;;
            0) exit 0 ;;
            *) echo "选择无效。"; pause ;;
        esac
    done
}

usage() {
    cat <<EOF
用法：
  sh udp2raw.sh              打开中文交互菜单
  sh udp2raw.sh menu         打开中文交互菜单
  sh udp2raw.sh install      仅执行覆盖安装/更新

环境变量：
  UDP2RAW_BIN=udp2raw_amd64
  UDP2RAW_BASE_URL=$BASE_URL
  UDP2RAW_BIN_DIR_URL=$BASE_URL/udp2raw_bin
EOF
}

main() {
    cmd="${1:-menu}"
    case "$cmd" in
        menu) menu ;;
        install)
            install_all
            print_next_steps
            ;;
        help|-h|--help) usage ;;
        *)
            usage
            exit 2
            ;;
    esac
}

main "$@"
