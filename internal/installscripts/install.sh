#!/bin/sh
# netnoodle installer. Compatible with dash and busybox ash.
set +x
set -eu
umask 077

fail() { printf '%s\n' "$*" >&2; exit 1; }
valid_name() { [ ${#1} -le 63 ] && printf '%s\n' "$1" | LC_ALL=C grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*$'; }

# This function only assigns known keys. Never execute setup data.
parse_code() {
    [ ${#1} -le 16384 ] || return 1
    case $1 in nnsetup1:*) encoded=${1#nnsetup1:} ;; *) return 1 ;; esac
    case $encoded in ''|*[!A-Za-z0-9_-]*) return 1 ;; esac
    case $((${#encoded} % 4)) in 0) pad='' ;; 2) pad='==' ;; 3) pad='=' ;; *) return 1 ;; esac
    decoded=$(printf '%s%s' "$encoded" "$pad" | tr '_-' '/+' | base64 -d) || return 1
    server='' fingerprint='' spki='' session='' secret='' token='' name='' kind='' version='' expires=''
    seen='|'
    while IFS= read -r line; do
        case $line in *=*) key=${line%%=*}; value=${line#*=} ;; *) return 1 ;; esac
        case $key in server|fingerprint|spki|session|secret|token|name|kind|version|expires)
            case $seen in *"|$key|"*) return 1 ;; esac
            seen=$seen$key'|'
            case $key in
                server) server=$value ;; fingerprint) fingerprint=$value ;; spki) spki=$value ;;
                session) session=$value ;; secret) secret=$value ;; token) token=$value ;;
                name) name=$value ;; kind) kind=$value ;; version) version=$value ;; expires) expires=$value ;;
            esac ;;
        esac
    done <<EOF
$decoded
EOF
    [ -n "$server" ] && [ -n "$fingerprint" ] && [ -n "$spki" ] && [ -n "$session" ] && [ -n "$secret" ] && [ -n "$token" ] && [ -n "$name" ] && [ -n "$kind" ] && [ -n "$version" ] && [ -n "$expires" ] || return 1
    valid_name "$name" || return 1
    [ ${#fingerprint} -eq 64 ] || return 1
    case $fingerprint in *[!a-fA-F0-9]*) return 1 ;; esac
    [ ${#session} -ge 16 ] && [ ${#session} -le 80 ] && [ ${#secret} -eq 43 ] && [ ${#token} -le 128 ] || return 1
    case $session in *[!A-Za-z0-9-]*) return 1 ;; esac
    case $secret$token in *[!A-Za-z0-9_-]*) return 1 ;; esac
    printf '%s\n' "$spki" | LC_ALL=C grep -Eq '^[A-Za-z0-9+/]{43}=$' || return 1
    printf '%s\n' "$server" | LC_ALL=C grep -Eq '^https://([A-Za-z0-9._-]+|\[[0-9A-Fa-f:]+\])(:[0-9]+)?$' || return 1
    printf '%s\n' "$version" | LC_ALL=C grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$' || return 1
    printf '%s\n' "$expires" | LC_ALL=C grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' || return 1
    case $kind in agent|agent-pull|scan|actor-host|actor-unifi|actor-proxmox) ;; *) return 1 ;; esac
}

# Check names separately from verbose types: verbose symlink listings end in
# their target, so checking only the last column would miss duplicate links.
check_archive_members() {
    tar -tzf "$1" > "$work/names" || return 1
    awk -v b="$2" -v u="$3" '$0==b || (u!="" && $0==u) { count[$0]++ } END { if(count[b]!=1 || (u!="" && count[u]!=1)) exit 1 }' "$work/names" || return 1
    tar -tvzf "$1" > "$work/list" || return 1
    awk -v b="$2" -v u="$3" '$NF==b || (u!="" && $NF==u) { if(substr($1,1,1)!="-") bad=1; count[$NF]++ } END { if(bad || count[b]!=1 || (u!="" && count[u]!=1)) exit 1 }' "$work/list"
}

# Every entry is durable before its resource is created. The journal is root
# owned, outside the service's writable directory. It contains no secrets.
check_bootstrap() {
    [ -n "${NN_EXPECTED_SERVER:-}" ] && [ -n "${NN_EXPECTED_SPKI:-}" ] && [ -n "${NN_EXPECTED_FINGERPRINT:-}" ] &&
    [ "$server" = "$NN_EXPECTED_SERVER" ] && [ "$spki" = "$NN_EXPECTED_SPKI" ] && [ "$fingerprint" = "$NN_EXPECTED_FINGERPRINT" ]
}
record() { printf '%s|%s\n' "$1" "$2" >> "$journal"; }
make_dir() { if [ ! -d "$1" ]; then [ ! -e "$1" ] && [ ! -L "$1" ] || return 1; record dir "$1"; mkdir "$1"; fi; }
make_file() { [ ! -e "$1" ] && [ ! -L "$1" ] || return 1; record file "$1"; }
check_install_root() {
    [ ! -L "$install_root" ] || fail 'Install root must not be a link.'
    [ "$(stat -c %u "$install_root")" = 0 ] || fail 'Install root must be owned by root.'
    mode=$(stat -c %a "$install_root")
    [ "$((0$mode & 0022))" -eq 0 ] || fail 'Install root must not be writable by other users.'
    [ ! -L "$journal" ] || fail 'Journal must not be a link.'
}
rollback() {
    [ -f "$journal" ] || return 0
    reverse=$(mktemp) || return 1
    chmod 600 "$reverse"
    if ! awk '{ a[NR]=$0 } END { for(i=NR;i>0;i--) print a[i] }' "$journal" > "$reverse"; then
        rm -f -- "$reverse"; return 1
    fi
    rollback_bad=0
    while IFS='|' read -r type target; do
        # Refuse a corrupt journal, including paths outside the install root.
        case $type in
            unit) case $target in nn-*.service) systemctl stop "$target" || rollback_bad=1; systemctl disable "$target" || rollback_bad=1 ;; *) rollback_bad=1 ;; esac ;;
            file) case $target in *'/../'*|*'/..'|*'/./'*) rollback_bad=1 ;; "$install_root"/*|"$unit_root"/nn-*.service) rm -f -- "$target" || rollback_bad=1 ;; *) rollback_bad=1 ;; esac ;;
            dir) case $target in *'/../'*|*'/..'|*'/./'*) rollback_bad=1 ;; "$install_root"/*) rm -rf -- "$target" || rollback_bad=1 ;; *) rollback_bad=1 ;; esac ;;
            user) case $target in nni-*) if id "$target" >/dev/null 2>&1; then userdel "$target" || rollback_bad=1; fi ;; *) rollback_bad=1 ;; esac ;;
            *) rollback_bad=1 ;;
        esac
    done < "$reverse"
    rm -f -- "$reverse" || rollback_bad=1
    systemctl daemon-reload || rollback_bad=1
    if [ "$rollback_bad" -ne 0 ]; then printf '%s\n' 'Rollback had errors. Keep the journal and check the service and files.' >&2; return 1; fi
    rm -f -- "$journal" || return 1
    printf '%s\n' 'Removed the service, files, directories and user made by this install.'
}

# Keep curl secrets out of the process arguments. Each request has a timeout.
pinned() { curl -q -fsSk --proto '=https' --max-time 30 --max-filesize 1048576 --pinnedpubkey "sha256//$spki" "$@"; }
session_call() {
    method=$1; suffix=$2; payload=$3
    printf 'X-NN-Onboard-Secret: %s\n' "$secret" > "$work/header"
    printf '%s' "$payload" > "$work/request"
    pinned -X "$method" -H @"$work/header" -H 'Content-Type: application/json' --data-binary @"$work/request" "$server/v1/onboard/$session$suffix"
}
report() { session_call POST /step "{\"name\":\"$1\",\"ok\":true,\"message\":\"\"}" > /dev/null; }
ask() { [ "$yes" -eq 0 ] || fail "Input is required: $1. Run without --yes."; printf '%s: ' "$1" > /dev/tty; IFS= read -r answer < /dev/tty; [ -n "$answer" ] && [ ${#answer} -le 16384 ] || fail 'Input is empty or too large.'; }
ask_secret() {
    [ "$yes" -eq 0 ] || fail 'A secret is required. Run without --yes.'
    printf '%s: ' "$1" > /dev/tty
    tty_state=$(stty -g < /dev/tty); stty -echo < /dev/tty
    IFS= read -r answer < /dev/tty || { stty "$tty_state" < /dev/tty; tty_state=''; return 1; }
    stty "$tty_state" < /dev/tty; tty_state=''; printf '\n' > /dev/tty
    [ -n "$answer" ] && [ ${#answer} -le 16384 ] || fail 'Secret is empty or too large.'
}
json_safe() { printf '%s\n' "$1" | LC_ALL=C grep -Eq '^[A-Za-z0-9._:/@! =,+*-]+$'; }

cleanup() {
    rc=$?; trap - EXIT INT TERM
    [ -z "${tty_state:-}" ] || stty "$tty_state" < /dev/tty
    if [ "$armed" -eq 1 ] && [ "$success" -eq 0 ]; then
        printf '%s\n' "Install failed at: $stage. Rolling back." >&2
        session_call POST /step "{\"name\":\"$stage\",\"ok\":false,\"message\":\"installer failed; local rollback attempted\"}" >/dev/null || printf '%s\n' 'Could not report the failed step.' >&2
        if [ "$journal_active" -eq 1 ]; then rollback || rc=1; fi
        session_call POST /abort "{\"reason\":\"installer failed at $stage; local rollback attempted\"}" >/dev/null || { printf '%s\n' 'Server abort failed. Cancel the session on the Peers page.' >&2; rc=1; }
    fi
    [ -z "$work" ] || rm -rf -- "$work"
    exit "$rc"
}

main() {
    [ "$(/usr/bin/id -u)" -eq 0 ] || fail 'Run the pinned one-liner with sudo; this script does not elevate itself.'
    PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
    unset TMPDIR TMP TEMP TAR_OPTIONS CURL_HOME SSL_CERT_FILE SSL_CERT_DIR LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_PROFILE LIBPATH SHLIB_PATH ENV BASH_ENV CDPATH GZIP BZIP2 XZ_OPT XZ_DEFAULTS
    code=${NN_SETUP_CODE:-}; unset NN_SETUP_CODE; yes=0 uninstall=''
    while [ "$#" -gt 0 ]; do
        case $1 in
            --code) fail '--code is unsafe; use NN_SETUP_CODE or hidden interactive input.' ;;
            --yes) yes=1; shift ;;
            --uninstall) [ "$#" -ge 2 ] || fail '--uninstall needs a name'; uninstall=$2; shift 2 ;;
            *) fail 'Unknown installer option.' ;;
        esac
    done
    [ "$(uname -s)" = Linux ] || fail 'This installer needs Linux.'
    command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || fail 'This installer needs systemd.'
    install_root=/var/lib/nn-install; unit_root=/etc/systemd/system
    if [ -n "$uninstall" ]; then
        valid_name "$uninstall" || fail 'Invalid name'
        journal=$install_root/$uninstall.journal
        if [ -e "$install_root" ] || [ -L "$install_root" ]; then check_install_root; rollback; fi
        return
    fi
    [ -n "${NN_EXPECTED_SERVER:-}" ] && [ -n "${NN_EXPECTED_SPKI:-}" ] && [ -n "${NN_EXPECTED_FINGERPRINT:-}" ] || fail 'Missing bootstrap trust values; use the pinned one-liner.'
    case $(uname -m) in x86_64) arch=x86_64 ;; aarch64) arch=aarch64 ;; armv7l) arch=armv7 ;; *) fail 'Supported architectures: x86_64, aarch64, armv7l.' ;; esac
    for tool in curl base64 sha256sum tar awk sed grep date df mktemp useradd userdel stat sort head cut; do command -v "$tool" >/dev/null 2>&1 || fail "Missing program: $tool"; done
    work='' armed=0 success=0 journal_active=0 stage=setup
    trap cleanup EXIT; trap 'exit 130' INT; trap 'exit 143' TERM
    if [ -z "$code" ]; then ask_secret 'Paste the setup code'; code=$answer; fi
    parse_code "$code" || fail 'Invalid setup code.'; unset code decoded encoded
    check_bootstrap || fail 'Setup code does not match bootstrap trust values.'
    # ISO UTC strings have the same sort order as time. GNU date and busybox
    # date both print this format; neither must parse RFC 3339.
    now=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    [ "$(printf '%s\n%s\n' "$now" "$expires" | LC_ALL=C sort | head -n 1)" = "$now" ] && [ "$now" != "$expires" ] || fail 'The setup code has expired.'
    work=$(mktemp -d /var/lib/nn-bootstrap.XXXXXXXXXX); chmod 700 "$work"; stage=preflight
    journal=$install_root/$name.journal
    pinned -D "$work/headers" "$server/v1/health" > "$work/health"
    # Compare the HTTP Date to local UTC without nonportable date parsing.
    remote=$(sed -n 's/^[Dd][Aa][Tt][Ee]: *//p' "$work/headers" | tr -d '\r')
    remote_epoch=$(printf '%s\n' "$remote" | awk '
        BEGIN { split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec",a," "); for(i=1;i<=12;i++) months[a[i]]=i }
        NF==6 && $6=="GMT" && ($3 in months) {
            y=$4; m=months[$3]; d=$2; split($5,t,":");
            if(m<=2) { y--; m+=12 }
            days=365*y+int(y/4)-int(y/100)+int(y/400)+int((153*(m-3)+2)/5)+d-1-719468;
            printf "%.0f", days*86400+t[1]*3600+t[2]*60+t[3]
        }')
    [ -n "$remote_epoch" ] || fail 'Server Date header is missing.'
    delta=$(($(date +%s) - remote_epoch))
    [ "$delta" -gt -300 ] && [ "$delta" -lt 300 ] || fail 'Set the clock. The server time differs by more than 5 minutes.'
    free=$(df -Pk /var/lib | awk 'END {print $4}')
    [ "$free" -ge 262144 ] || fail 'At least 256 MiB of free disk is required.'
    report preflight
    armed=1
    stage=download
    pinned "$server/v1/install/manifest?version=$version&platform=linux-$arch&kind=$kind" > "$work/manifest"
    artifact=$(sed -n 's/.*"url":"\([^"]*\)".*/\1/p' "$work/manifest")
    checksum=$(sed -n 's/.*"sha256":"\([a-f0-9]*\)".*/\1/p' "$work/manifest")
    case $artifact in https://*) ;; *) fail 'Invalid artifact URL.' ;; esac
    [ ${#checksum} -eq 64 ] || fail 'Missing SHA-256 checksum.'
    # Release downloads use normal PKI; server requests always use its pin.
    curl -q -fsSL --proto '=https' --proto-redir '=https' --max-time 300 --max-filesize 268435456 "$artifact" -o "$work/release.tar.gz"
    [ "$(sha256sum "$work/release.tar.gz" | awk '{print $1}')" = "$checksum" ] || fail 'SHA-256 check failed.'
    package=${artifact##*/}; package=${package%.tar.gz}
    case $package in *[!A-Za-z0-9._-]*|'') fail 'Invalid package name.' ;; esac
    case $kind in agent*) binary=nn-agent; template=nn-agent.service; [ "$kind" != agent-pull ] || template=nn-agent-serve.service; unit_path=$package/$template ;;
        scan) binary=nn-scan; template=''; unit_path='' ;;
        actor-*) binary=nn-actor; template=nn-actor-host.service; unit_path=$package/deploy/$template ;;
    esac
    # Extract only known regular files. A signed archive must still not write
    # absolute paths, links, or unrequested archive members as root.
    check_archive_members "$work/release.tar.gz" "$package/$binary" "$unit_path" || fail 'Invalid archive members.'
    mkdir "$work/unpack"
    if [ -n "$unit_path" ]; then tar -xzf "$work/release.tar.gz" -C "$work/unpack" "$package/$binary" "$unit_path"; else tar -xzf "$work/release.tar.gz" -C "$work/unpack" "$package/$binary"; fi
    [ -f "$work/unpack/$package/$binary" ] && [ ! -L "$work/unpack/$package/$binary" ] || fail 'Binary is not a regular file.'
    if [ -n "$unit_path" ]; then [ -f "$work/unpack/$unit_path" ] && [ ! -L "$work/unpack/$unit_path" ] || fail 'Unit is not a regular file.'; fi
    report download
    stage=install
    # Validate the journal's parent before trusting an existing journal.
    [ ! -L "$install_root" ] || fail 'Install root must not be a link.'
    if [ ! -d "$install_root" ]; then mkdir -m 711 "$install_root"; fi
    check_install_root
    if [ -e "$journal" ]; then
        ask 'An install exists. Type repair to remove it and install again, or abort'
        [ "$answer" = repair ] || fail 'Install cancelled.'
        rollback || fail 'Repair rollback failed.'
    fi
    # The shared journal directory is retained for other installs.
    [ ! -e "$journal" ] && [ ! -L "$journal" ] || fail 'Journal exists.'
    : > "$journal"; chmod 600 "$journal"
    journal_active=1
    install_home=$install_root/$name
    [ ! -e "$install_home" ] && [ ! -L "$install_home" ] || fail 'Install directory exists without a journal.'
    make_dir "$install_home"
    user=nni-$(printf '%s' "$name" | sha256sum | cut -c1-16)
    id "$user" >/dev/null 2>&1 && fail 'Install user already exists.'
    record user "$user"; useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
    group=$(id -gn "$user")
    make_file "$install_home/$binary"; cp -P "$work/unpack/$package/$binary" "$install_home/$binary"; chmod 755 "$install_home/$binary"
    state=$install_home/state; make_dir "$state"
    creds=$install_home/credentials.json; config=$install_home/config.json
    make_file "$creds"; make_file "$config"
    case $kind in
        agent*) printf '{"credentials":"%s","pull_state":"%s/pull.json","interval":"1h"}\n' "$creds" "$state" > "$config" ;;
        scan) ask 'Scan CIDR (for example 192.168.1.0/24)'; printf '%s\n' "$answer" | grep -Eq '^[0-9a-fA-F.:]+/[0-9]+$' || fail 'Invalid CIDR'; printf '{"credentials":"%s","cidrs":["%s"],"interval":"15m"}\n' "$creds" "$answer" > "$config" ;;
        actor-*)
            backend=${kind#actor-}; settings='{}'
            case $backend in
                host) ask 'Agent peer name of this host'; valid_name "$answer" || fail 'Invalid agent name'; settings="{\"agent\":\"$answer\",\"services\":[]}" ;;
                unifi|proxmox)
                    ask 'API HTTPS URL'; api_url=$answer; json_safe "$api_url" || fail 'Invalid URL'; case $api_url in https://*) ;; *) fail 'HTTPS is required' ;; esac
                    ask 'API certificate SHA-256 fingerprint'; api_fp=$answer; [ ${#api_fp} -eq 64 ] || fail 'Invalid fingerprint'; case $api_fp in *[!a-fA-F0-9]*) fail 'Invalid fingerprint' ;; esac
                    secret_file=$install_home/api-secret; make_file "$secret_file"
                    if [ "$backend" = unifi ]; then
                        ask_secret 'UniFi API key'; printf '%s' "$answer" > "$secret_file"; unset answer
                        ask 'Protected gateway, controller or server MAC'; protected=$answer; printf '%s\n' "$protected" | grep -Eq '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$' || fail 'Invalid MAC'
                        settings="{\"url\":\"$api_url\",\"fingerprint\":\"$api_fp\",\"api_key_file\":\"$secret_file\",\"site\":\"default\",\"never_block\":[\"$protected\"]}"
                    else
                        ask 'Proxmox token ID'; token_id=$answer; json_safe "$token_id" || fail 'Invalid token ID'
                        ask 'Proxmox source name'; source=$answer; valid_name "$source" || fail 'Invalid source'
                        ask_secret 'Proxmox token secret'; printf '%s' "$answer" > "$secret_file"; unset answer
                        settings="{\"url\":\"$api_url\",\"fingerprint\":\"$api_fp\",\"token_id\":\"$token_id\",\"token_secret_file\":\"$secret_file\",\"source\":\"$source\",\"allow_empty_never_isolate\":true}"
                    fi ;;
            esac
            # No actions are allowed until the operator edits the local policy.
            make_file "$state/nonces.json"
            printf '{"credentials":"%s","nonce_file":"%s/nonces.json","dry_run":true,"backends":[{"type":"%s","name":"%s","settings":%s}],"allow":[]}\n' "$creds" "$state" "$backend" "$backend" "$settings" > "$config" ;;
    esac
    report install
    stage=enroll
    export NN_JOIN_TOKEN="$token"
    case $kind in
        agent*) "$install_home/$binary" --config "$config" --creds "$creds" enroll --server "$server" --fingerprint "$fingerprint" --name "$name" ;;
        *) "$install_home/$binary" enroll -server "$server" -fingerprint "$fingerprint" -name "$name" -creds "$creds" ;;
    esac
    unset NN_JOIN_TOKEN token
    if [ "$kind" = agent-pull ]; then
        ask 'Agent address reachable from the server (host:7444)'; address=$answer
        json_safe "$address" || fail 'Invalid address'
        session_call POST /step "{\"name\":\"pair\",\"ok\":true,\"message\":\"$address\"}" > "$work/pair"
        pair_code=$(sed -n 's/.*"code":"\([A-Z2-7]*\)".*/\1/p' "$work/pair")
        pull_fp=$(sed -n 's/.*"fingerprint":"\([a-f0-9]*\)".*/\1/p' "$work/pair")
        [ -n "$pair_code" ] && [ ${#pull_fp} -eq 64 ] || fail 'Invalid pairing response'
        make_file "$state/pull.json"
        ask 'Local listen address (for example 0.0.0.0:7444)'; listen=$answer
        NN_PAIR_CODE="$pair_code" "$install_home/$binary" --config "$config" pair --server-fingerprint "$pull_fp" --listen "$listen"
        unset pair_code
    fi
    report enrolled
    unit=nn-$name.service; unit_file=$unit_root/$unit
    make_file "$unit_file"
    if [ -n "$template" ]; then
        # Use the shipped sandbox; replace only this installation's paths and
        # identity. Other actors do not need the host actor's capabilities.
        if [ "$binary" = nn-agent ]; then
            mode=run; [ "$kind" != agent-pull ] || mode=serve
            exec_start="$install_home/$binary --config $config $mode"
        else
            exec_start="$install_home/$binary run -config $config"
        fi
        sed -e "s|^ExecStart=.*|ExecStart=$exec_start|" \
            -e "s|^User=.*|User=$user|" -e "s|^Group=.*|Group=$group|" \
            -e "s|^WorkingDirectory=.*|WorkingDirectory=$install_home|" -e '/^StateDirectory/d' \
            -e "s|^ReadWritePaths=.*|ReadWritePaths=$state|" \
            "$work/unpack/$unit_path" > "$unit_file"
        if [ "$kind" = actor-unifi ] || [ "$kind" = actor-proxmox ]; then
            sed '/^AmbientCapabilities=/d; s/^CapabilityBoundingSet=.*/CapabilityBoundingSet=/' "$unit_file" > "$work/unit"; cp "$work/unit" "$unit_file"
        fi
    else
        # The release has no scanner unit. Use the same basic sandbox.
        printf '[Unit]\nDescription=netnoodle scanner\nAfter=network-online.target\n[Service]\nExecStart=%s/nn-scan run -config %s\nUser=%s\nGroup=%s\nRestart=on-failure\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nReadWritePaths=%s\n[Install]\nWantedBy=multi-user.target\n' "$install_home" "$config" "$user" "$group" "$state" > "$unit_file"
    fi
    chmod 644 "$unit_file"
    # Allow the dedicated user to traverse only its own installation.
    "$install_home/$binary" --version
    chmod 711 "$install_root"
    chown -R "root:$group" "$install_home"; chmod 750 "$install_home"
    find "$install_home" -type f -exec chmod 640 {} \;
    chmod 750 "$install_home/$binary"
    chown -R "$user:$group" "$state"; chmod 700 "$state"
    stage=service
    record unit "$unit"
    systemctl daemon-reload; systemctl enable --now "$unit"
    systemctl is-active --quiet "$unit"
    report service
    stage=communication
    deadline=$(($(date +%s) + 120))
    peer_seen=0
    while [ "$(date +%s)" -lt "$deadline" ]; do
        systemctl is-active --quiet "$unit" || fail 'Service stopped.'
        # GET has no body. The secret stays in the private header file.
        remaining=$((deadline - $(date +%s)))
        [ "$remaining" -gt 0 ] || break
        pinned --max-time "$remaining" -H @"$work/header" "$server/v1/onboard/$session" > "$work/status"
        if grep -Eq '"peer_seen"[[:space:]]*:[[:space:]]*true' "$work/status"; then peer_seen=1; break; fi
        if grep -Eq '"state":"(expired|aborted)"' "$work/status"; then fail 'Session ended.'; fi
        remaining=$((deadline - $(date +%s)))
        [ "$remaining" -gt 0 ] || break
        if [ "$remaining" -gt 2 ]; then sleep 2; else sleep "$remaining"; fi
    done
    [ "$peer_seen" -eq 1 ] || fail 'No communication from the peer within 120 seconds.'
    report communication; report done
    success=1
    printf 'Installed %s\nServer: %s\nService: %s\nUninstall: sh install.sh --uninstall %s\n' "$name" "$server" "$unit" "$name"
}

# Tests source the functions without starting an installation.
if [ "${NN_INSTALL_LIBRARY:-}" != 1 ]; then main "$@"; fi
