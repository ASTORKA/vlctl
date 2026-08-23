#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vlctl — CLI-клиент для vless:// ссылок (VLESS / REALITY / XTLS-Vision).

Своей реализации протокола тут нет: VLESS+REALITY+XTLS-Vision слишком тяжёл,
чтобы писать его с нуля. Утилита — тонкая обёртка над готовым ядром:
ссылка -> JSON-конфиг -> запуск xray-core (SOCKS) или sing-box (TUN).

Запуск без аргументов открывает интерактивное меню: выбрать сохранённое
подключение или добавить новую ссылку и дать ей название.

Неинтерактивные команды (для скриптов):
  vlctl up   <ссылка|профиль> [--tun]     поднять подключение
  vlctl test <ссылка|профиль>             проверить, куда выходит трафик
  vlctl config <ссылка|профиль> [--tun]   напечатать JSON-конфиг ядра
  vlctl save <имя> <ссылка> | vlctl rename <старое> <новое> | vlctl rm <имя>
  vlctl import <url|файл>                 импортировать подписку
  vlctl ls
  vlctl install [--sing-box]              скачать ядро в ~/.local/share/vlctl/bin
"""

import argparse
import base64
import json
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from urllib.parse import parse_qs, unquote, urlparse

HOME = os.path.expanduser("~")
CFG_DIR = os.path.join(os.environ.get("XDG_CONFIG_HOME", os.path.join(HOME, ".config")), "vlctl")
BIN_DIR = os.path.join(os.environ.get("XDG_DATA_HOME", os.path.join(HOME, ".local", "share")), "vlctl", "bin")
STORE = os.path.join(CFG_DIR, "profiles.json")


# ---------------------------------------------------------------- вывод и ввод

def _c(code, s):
    return s if not sys.stdout.isatty() else "\033[%sm%s\033[0m" % (code, s)


def bold(s):
    return _c("1", s)


def dim(s):
    return _c("2", s)


def info(s):
    print(_c("32", "→ ") + s, file=sys.stderr)


def warn(s):
    print(_c("33", "! ") + s, file=sys.stderr)


def die(s, code=1):
    print(_c("31", "ОШИБКА: ") + s, file=sys.stderr)
    sys.exit(code)


class Abort(Exception):
    """Пользователь нажал Ctrl+C / Ctrl+D в диалоге — вернуться назад."""


def ask(prompt, default=None, allow_empty=False):
    suffix = " [%s]" % default if default else ""
    while True:
        try:
            v = input("%s%s: " % (prompt, suffix)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            raise Abort()
        if not v and default is not None:
            return default
        if v or allow_empty:
            return v


def confirm(prompt, default=True):
    hint = "Y/n" if default else "y/N"
    try:
        v = input("%s [%s]: " % (prompt, hint)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        raise Abort()
    if not v:
        return default
    return v in ("y", "yes", "д", "да")


# ---------------------------------------------------------------- парсинг ссылки

def parse_link(link, fatal=True):
    """vless://uuid@host:port?params#name -> dict."""
    link = (link or "").strip()
    err = None
    u = urlparse(link)
    if u.scheme != "vless":
        err = "поддерживается только схема vless://, получено: %r" % (u.scheme or link[:32])
    elif not u.username:
        err = "в ссылке нет UUID"
    elif not u.hostname:
        err = "в ссылке нет адреса сервера"
    if err:
        if fatal:
            die(err)
        raise ValueError(err)

    q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
    return {
        "raw": link,
        "uuid": unquote(u.username),
        "host": u.hostname,
        "port": u.port or 443,
        "name": unquote(u.fragment) if u.fragment else "%s:%s" % (u.hostname, u.port or 443),
        "flow": q.get("flow", ""),
        "net": q.get("type", "tcp"),
        "security": q.get("security", "none"),
        "sni": q.get("sni") or q.get("peer") or "",
        "fp": q.get("fp", "chrome"),
        "pbk": q.get("pbk", ""),
        "sid": q.get("sid", ""),
        "spx": q.get("spx", ""),
        "alpn": [a for a in q.get("alpn", "").split(",") if a],
        "path": unquote(q.get("path", "")) or "/",
        "hostHeader": q.get("host", ""),
        "serviceName": q.get("serviceName", ""),
        "headerType": q.get("headerType", "none"),
        "insecure": q.get("allowInsecure", "0") in ("1", "true"),
    }


def describe(p):
    return "%s:%s  %s/%s" % (p["host"], p["port"], p["net"], p["security"])


# ---------------------------------------------------------------- конфиг xray

def xray_stream(p):
    ss = {"network": p["net"]}

    if p["security"] == "reality":
        if not p["pbk"]:
            die("security=reality, но в ссылке нет pbk (публичного ключа)")
        ss["security"] = "reality"
        ss["realitySettings"] = {
            "serverName": p["sni"] or p["host"],
            "fingerprint": p["fp"] or "chrome",
            "publicKey": p["pbk"],
            "shortId": p["sid"],
            "spiderX": p["spx"] or "/",
        }
    elif p["security"] in ("tls", "xtls"):
        ss["security"] = "tls"
        t = {"serverName": p["sni"] or p["host"], "fingerprint": p["fp"] or "chrome"}
        if p["alpn"]:
            t["alpn"] = p["alpn"]
        if p["insecure"]:
            t["allowInsecure"] = True
        ss["tlsSettings"] = t
    else:
        ss["security"] = "none"

    net = p["net"]
    if net in ("tcp", "raw") and p["headerType"] == "http":
        ss["tcpSettings"] = {"header": {"type": "http",
                                        "request": {"headers": {"Host": [p["hostHeader"] or p["host"]]}}}}
    elif net == "ws":
        w = {"path": p["path"]}
        if p["hostHeader"]:
            w["host"] = p["hostHeader"]
        ss["wsSettings"] = w
    elif net == "httpupgrade":
        ss["httpupgradeSettings"] = {"path": p["path"], "host": p["hostHeader"] or p["host"]}
    elif net == "xhttp":
        ss["xhttpSettings"] = {"path": p["path"], "host": p["hostHeader"] or p["host"]}
    elif net == "grpc":
        ss["grpcSettings"] = {"serviceName": p["serviceName"]}
    return ss


def xray_config(p, socks_port, http_port, log_level="warning"):
    user = {"id": p["uuid"], "encryption": "none"}
    if p["flow"]:
        user["flow"] = p["flow"]

    inbounds = [{
        "tag": "socks",
        "listen": "127.0.0.1",
        "port": socks_port,
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": True},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
    }]
    if http_port:
        inbounds.append({
            "tag": "http",
            "listen": "127.0.0.1",
            "port": http_port,
            "protocol": "http",
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    return {
        "log": {"loglevel": log_level},
        "inbounds": inbounds,
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{"address": p["host"], "port": p["port"], "users": [user]}]},
                "streamSettings": xray_stream(p),
            },
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}],
        },
    }


# ---------------------------------------------------------------- конфиг sing-box (TUN)

def tun_unsupported(p):
    """sing-box умеет не всё, что умеет xray. -> текст проблемы или None."""
    if p["net"] in ("xhttp", "splithttp"):
        return ("sing-box не поддерживает транспорт xhttp — TUN-режим для этого сервера недоступен.\n"
                "  Используй пункт 1 (SOCKS5 на xray-core), он с xhttp работает.")
    if p["net"] in ("tcp", "raw") and p["headerType"] == "http":
        return ("sing-box не поддерживает маскировку headerType=http — TUN-режим недоступен.\n"
                "  Используй пункт 1 (SOCKS5 на xray-core).")
    return None


def singbox_outbound(p):
    o = {
        "type": "vless",
        "tag": "proxy",
        "server": p["host"],
        "server_port": p["port"],
        "uuid": p["uuid"],
        "packet_encoding": "xudp",
    }
    if p["flow"]:
        o["flow"] = p["flow"]

    if p["security"] in ("reality", "tls", "xtls"):
        tls = {"enabled": True, "server_name": p["sni"] or p["host"]}
        if p["fp"]:
            tls["utls"] = {"enabled": True, "fingerprint": p["fp"]}
        if p["alpn"]:
            tls["alpn"] = p["alpn"]
        if p["insecure"]:
            tls["insecure"] = True
        if p["security"] == "reality":
            tls["reality"] = {"enabled": True, "public_key": p["pbk"], "short_id": p["sid"]}
        o["tls"] = tls

    net = p["net"]
    if net == "ws":
        o["transport"] = {"type": "ws", "path": p["path"],
                          "headers": {"Host": p["hostHeader"] or p["host"]}}
    elif net == "grpc":
        o["transport"] = {"type": "grpc", "service_name": p["serviceName"]}
    elif net == "httpupgrade":
        o["transport"] = {"type": "httpupgrade", "path": p["path"],
                          "host": p["hostHeader"] or p["host"]}
    return o


def singbox_version(binary):
    """(major, minor) установленного sing-box; (1, 12) если распознать не вышло."""
    try:
        out = subprocess.run([binary, "version"], capture_output=True, timeout=10).stdout.decode(errors="replace")
    except Exception:
        return (1, 12)
    m = re.search(r"version (\d+)\.(\d+)", out)
    return (int(m.group(1)), int(m.group(2))) if m else (1, 12)


def singbox_config(p, dns="1.1.1.1", log_level="warn", modern=True):
    """modern=True — формат sing-box 1.12+; False — legacy (1.11 и старее)."""
    if modern:
        dns_block = {
            "servers": [
                {"type": "udp", "tag": "remote", "server": dns, "detour": "proxy"},
                {"type": "local", "tag": "local"},
            ],
            "final": "remote",
        }
    else:
        dns_block = {
            "servers": [
                {"tag": "remote", "address": dns, "detour": "proxy"},
                {"tag": "local", "address": "local", "detour": "direct"},
            ],
            "rules": [{"outbound": "any", "server": "local"}],
            "strategy": "prefer_ipv4",
            "final": "remote",
        }

    route = {
        "rules": [
            {"action": "sniff"},
            {"protocol": "dns", "action": "hijack-dns"},
            {"ip_is_private": True, "outbound": "direct"},
        ],
        "final": "proxy",
        "auto_detect_interface": True,
    }
    if modern:
        # Адрес сервера — домен, его нужно резолвить в обход туннеля.
        route["default_domain_resolver"] = {"server": "local"}

    return {
        "log": {"level": log_level, "timestamp": True},
        "dns": dns_block,
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": 1500,
            "auto_route": True,
            "strict_route": True,
            "stack": "system",
        }],
        "outbounds": [
            singbox_outbound(p),
            {"type": "direct", "tag": "direct"},
        ],
        "route": route,
    }


# ---------------------------------------------------------------- хранилище профилей

def load_store():
    """-> {"profiles": {имя: ссылка}, "last": имя}. Понимает и старый плоский формат."""
    try:
        with open(STORE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"profiles": {}, "last": None}
    except ValueError:
        warn("%s повреждён, начинаю с пустого списка" % STORE)
        return {"profiles": {}, "last": None}

    if isinstance(data, dict) and "profiles" in data:
        data.setdefault("last", None)
        return data
    return {"profiles": data if isinstance(data, dict) else {}, "last": None}


def save_store(store):
    os.makedirs(CFG_DIR, mode=0o700, exist_ok=True)
    store["version"] = 2
    tmp = STORE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(store, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STORE)


def unique_name(profiles, wanted, link=None):
    """Свободное имя: к занятому добавляем -2, -3… (если это не та же ссылка)."""
    name = re.sub(r"\s+", " ", wanted).strip() or "node"
    base, n = name, 2
    while name in profiles and profiles[name] != link:
        name = "%s-%d" % (base, n)
        n += 1
    return name


def add_profile(link, name=None):
    p = parse_link(link)
    store = load_store()
    name = unique_name(store["profiles"], name or p["name"], link)
    store["profiles"][name] = link.strip()
    store["last"] = name
    save_store(store)
    return name


def touch_last(name):
    store = load_store()
    if store.get("last") != name and name in store["profiles"]:
        store["last"] = name
        save_store(store)


def resolve(arg):
    """Аргумент — либо сама ссылка, либо имя (или часть имени) сохранённого профиля."""
    if arg.startswith("vless://"):
        return parse_link(arg)
    profs = load_store()["profiles"]
    if arg in profs:
        return parse_link(profs[arg])
    matches = [k for k in profs if arg.lower() in k.lower()]
    if len(matches) == 1:
        return parse_link(profs[matches[0]])
    if len(matches) > 1:
        die("под «%s» подходит несколько профилей: %s" % (arg, ", ".join(matches)))
    die("не ссылка и не сохранённый профиль: %r (список: vlctl ls)" % arg)


# ---------------------------------------------------------------- бинарники ядра

def find_bin(name):
    local = os.path.join(BIN_DIR, name)
    if os.path.isfile(local) and os.access(local, os.X_OK):
        return local
    return shutil.which(name)


def need_bin(name):
    b = find_bin(name)
    if b:
        return b
    flag = " --sing-box" if name == "sing-box" else ""
    if sys.stdin.isatty():
        warn("ядро %s не найдено." % name)
        try:
            if confirm("Скачать его сейчас в %s?" % BIN_DIR):
                install_core(sing_box=(name == "sing-box"))
                b = find_bin(name)
                if b:
                    return b
        except Abort:
            pass
    die("не найден %s. Поставь пакетом или выполни: vlctl install%s" % (name, flag))


def arch_tag(kind):
    m = platform.machine().lower()
    sysname = platform.system().lower()
    if kind == "xray":
        table = {"x86_64": "64", "amd64": "64", "aarch64": "arm64-v8a", "arm64": "arm64-v8a"}
        a = table.get(m)
        if not a:
            die("неизвестная архитектура %s" % m)
        return "Xray-%s-%s.zip" % ("linux" if sysname == "linux" else "macos", a)
    table = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
    a = table.get(m)
    if not a:
        die("неизвестная архитектура %s" % m)
    return a


def http_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "vlctl"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def install_core(sing_box=False):
    os.makedirs(BIN_DIR, exist_ok=True)
    if sing_box:
        info("узнаю последний релиз sing-box…")
        rel = json.loads(http_get("https://api.github.com/repos/SagerNet/sing-box/releases/latest"))
        tag = rel["tag_name"].lstrip("v")
        osn = "linux" if platform.system().lower() == "linux" else "darwin"
        fname = "sing-box-%s-%s-%s.tar.gz" % (tag, osn, arch_tag("sing-box"))
        url = "https://github.com/SagerNet/sing-box/releases/download/v%s/%s" % (tag, fname)
        info("качаю %s" % url)
        blob = http_get(url)
        dst = os.path.join(BIN_DIR, "sing-box")
        with tempfile.TemporaryDirectory() as td:
            tp = os.path.join(td, fname)
            with open(tp, "wb") as f:
                f.write(blob)
            subprocess.check_call(["tar", "-xzf", tp, "-C", td])
            for root, _, files in os.walk(td):
                if "sing-box" in files and root != td:
                    shutil.copy2(os.path.join(root, "sing-box"), dst)
                    break
            else:
                die("в архиве не нашёлся бинарник sing-box")
        os.chmod(dst, 0o755)
        info("готово: %s" % dst)
        return

    fname = arch_tag("xray")
    url = "https://github.com/XTLS/Xray-core/releases/latest/download/%s" % fname
    info("качаю %s" % url)
    blob = http_get(url)
    with tempfile.TemporaryDirectory() as td:
        zp = os.path.join(td, fname)
        with open(zp, "wb") as f:
            f.write(blob)
        with zipfile.ZipFile(zp) as z:
            z.extract("xray", BIN_DIR)
            for extra in ("geoip.dat", "geosite.dat"):
                try:
                    z.extract(extra, BIN_DIR)
                except KeyError:
                    pass
    os.chmod(os.path.join(BIN_DIR, "xray"), 0o755)
    info("готово: %s/xray" % BIN_DIR)


# ---------------------------------------------------------------- запуск ядра

class Opts(object):
    """Настройки запуска: и из argparse, и из интерактивного меню."""

    def __init__(self, socks_port=10808, http_port=10809, dns="1.1.1.1", verbose=False, tun=False):
        self.socks_port = socks_port
        self.http_port = http_port
        self.dns = dns
        self.verbose = verbose
        self.tun = tun

    @classmethod
    def from_args(cls, a):
        return cls(getattr(a, "socks_port", 10808), getattr(a, "http_port", 10809),
                   getattr(a, "dns", "1.1.1.1"), getattr(a, "verbose", False),
                   getattr(a, "tun", False))


def free_port(preferred):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", preferred))
        return preferred
    except OSError:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def write_tmp_config(cfg, prefix):
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=".json")
    os.write(fd, json.dumps(cfg, ensure_ascii=False, indent=2).encode())
    os.close(fd)
    os.chmod(path, 0o600)
    return path


def _wait(proc, grace=5):
    try:
        proc.wait()
    except KeyboardInterrupt:
        print()
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            proc.kill()
    return proc.returncode or 0


def _run(cmd, env=None, grace=5):
    return _wait(subprocess.Popen(cmd, env=env), grace)


def wait_port(port, seconds=5.0):
    for _ in range(int(seconds * 10)):
        time.sleep(0.1)
        s = socket.socket()
        s.settimeout(0.2)
        up = s.connect_ex(("127.0.0.1", port)) == 0
        s.close()
        if up:
            return True
    return False


def probe_ip(port, timeout=15):
    """Что видит внешний мир через SOCKS на этом порту. -> (текст, мс) или (None, ошибка)."""
    t0 = time.time()
    r = subprocess.run(["curl", "-s", "--max-time", str(timeout),
                        "-x", "socks5h://127.0.0.1:%d" % port,
                        "https://ifconfig.co/json"], capture_output=True)
    dt = (time.time() - t0) * 1000
    if r.returncode != 0 or not r.stdout.strip():
        return None, "curl rc=%d" % r.returncode
    try:
        d = json.loads(r.stdout)
        return "ip=%s  страна=%s %s  (%.0f мс)" % (d.get("ip"), d.get("country", "?"),
                                                   d.get("city", ""), dt), dt
    except ValueError:
        return r.stdout[:200].decode(errors="replace"), dt


def run_socks(p, o):
    xray = need_bin("xray")
    sp = free_port(o.socks_port)
    hp = free_port(o.http_port) if o.http_port else 0
    path = write_tmp_config(xray_config(p, sp, hp, "info" if o.verbose else "warning"), "vlctl-xray-")
    env = dict(os.environ)
    env.setdefault("XRAY_LOCATION_ASSET", BIN_DIR)

    info("сервер: %s (%s)" % (p["name"], describe(p)))
    info("SOCKS5: 127.0.0.1:%d%s" % (sp, " | HTTP: 127.0.0.1:%d" % hp if hp else ""))
    proc = subprocess.Popen([xray, "run", "-c", path], env=env)
    try:
        if wait_port(sp):
            txt, _ = probe_ip(sp)
            if txt:
                info("через прокси: %s" % txt)
            else:
                warn("прокси поднялся, но наружу не ходит — проверь ссылку (%s)" % _)
        print("""
  %s
  IP в браузере и в `curl` без прокси НЕ изменится: это прокси, а не VPN.
  Чтобы через туннель шло всё сразу — пункт 2 меню (VPN-режим, TUN).

  В терминале:
    export ALL_PROXY=socks5h://127.0.0.1:%d
    export HTTP_PROXY=http://127.0.0.1:%d HTTPS_PROXY=http://127.0.0.1:%d
  В Firefox: Настройки -> Сеть -> Вручную -> SOCKS5 127.0.0.1 порт %d,
             галочка «Проксировать DNS при использовании SOCKS v5».
  В Chrome:  google-chrome --proxy-server="socks5://127.0.0.1:%d"

  Остановить: Ctrl+C
""" % (bold("Работает только для приложений, которым указан этот прокси."),
       sp, hp or sp, hp or sp, sp, sp))
        return _wait(proc)
    finally:
        os.unlink(path)


def run_tun(p, o):
    bad = tun_unsupported(p)
    if bad:
        warn(bad)
        return 1
    sb = need_bin("sing-box")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        info("режим TUN требует root, перезапускаюсь через sudo…")
        fd, lf = tempfile.mkstemp(prefix="vlctl-link-")
        os.write(fd, p["raw"].encode())
        os.close(fd)
        os.chmod(lf, 0o600)
        os.execvp("sudo", ["sudo", "-E", sys.executable, os.path.abspath(__file__),
                           "up", "--tun", "--link-file", lf])

    ver = singbox_version(sb)
    cfg = singbox_config(p, o.dns, "info" if o.verbose else "warn", modern=ver >= (1, 12))
    path = write_tmp_config(cfg, "vlctl-sb-")
    info("сервер: %s (%s)" % (p["name"], describe(p)))
    info("ядро: sing-box %d.%d, режим TUN — весь трафик системы идёт через VPN. Остановить — Ctrl+C"
         % ver)
    try:
        return _run([sb, "run", "-c", path], grace=10)
    finally:
        os.unlink(path)


def connect(p, o):
    return run_tun(p, o) if o.tun else run_socks(p, o)


def check(p, o=None):
    """Поднять ядро на свободном порту и посмотреть, какой IP видит внешний мир."""
    o = o or Opts()
    xray = need_bin("xray")
    sp = free_port(0)
    path = write_tmp_config(xray_config(p, sp, 0), "vlctl-test-")
    env = dict(os.environ)
    env.setdefault("XRAY_LOCATION_ASSET", BIN_DIR)
    proc = subprocess.Popen([xray, "run", "-c", path],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        if not wait_port(sp):
            warn("ядро не поднялось:\n%s" % proc.stderr.read().decode(errors="replace")[-800:])
            return 1
        info("проверяю выход через «%s»…" % p["name"])
        txt, err = probe_ip(sp)
        if not txt:
            warn("не удалось выйти в сеть через прокси (%s)" % err)
            return 1
        print("%s  %s" % (_c("32", "OK"), txt))
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        os.unlink(path)


# ---------------------------------------------------------------- интерактивное меню

def ui_new_link(preset=None):
    """Спросить ссылку и название, сохранить. -> имя профиля или None."""
    print()
    link = preset or ask("Вставь vless:// ссылку")
    try:
        p = parse_link(link, fatal=False)
    except ValueError as e:
        warn(str(e))
        return None

    print("  сервер:   %s:%s" % (p["host"], p["port"]))
    print("  протокол: %s / %s%s" % (p["net"], p["security"], " / " + p["flow"] if p["flow"] else ""))
    if p["sni"]:
        print("  sni:      %s" % p["sni"])

    if not confirm("Сохранить эту ссылку?", True):
        return None
    name = ask("Название", p["name"])
    saved = add_profile(link, name)
    if saved != name:
        warn("такое название уже занято, сохранил как «%s»" % saved)
    info("сохранено: «%s»" % saved)
    return saved


def ui_profile(name):
    """Меню действий над одним подключением. -> True, если выйти в главное меню."""
    while True:
        store = load_store()
        link = store["profiles"].get(name)
        if not link:
            return True
        p = parse_link(link)

        print()
        print(bold("  %s" % name) + dim("   %s" % describe(p)))
        print("""    1) Подключиться   — SOCKS5 на 127.0.0.1 (без root)
    2) VPN-режим      — весь трафик системы через TUN (нужен root)%s
    3) Проверить      — какой IP видит внешний мир
    4) Переименовать
    5) Показать ссылку и конфиг
    6) Удалить
    0) Назад""" % ("" if not tun_unsupported(p) else dim("  [недоступно для этого сервера]")))
        ch = ask("Выбор", "1")

        if ch == "1":
            touch_last(name)
            connect(p, Opts())
        elif ch == "2":
            touch_last(name)
            connect(p, Opts(tun=True))
        elif ch == "3":
            touch_last(name)
            check(p)
        elif ch == "4":
            new = ask("Новое название", name)
            if new != name:
                store = load_store()
                fresh = unique_name(store["profiles"], new, link)
                store["profiles"] = {(fresh if k == name else k): v for k, v in store["profiles"].items()}
                if store.get("last") == name:
                    store["last"] = fresh
                save_store(store)
                info("теперь «%s»" % fresh)
                name = fresh
        elif ch == "5":
            print("\n" + link + "\n")
            if confirm("Показать JSON-конфиг ядра?", False):
                tun = confirm("Для TUN-режима (sing-box)?", False)
                print(json.dumps(singbox_config(p) if tun else xray_config(p, 10808, 10809),
                                 ensure_ascii=False, indent=2))
        elif ch == "6":
            if confirm("Удалить «%s»?" % name, False):
                store = load_store()
                store["profiles"].pop(name, None)
                if store.get("last") == name:
                    store["last"] = None
                save_store(store)
                info("удалено")
                return True
        elif ch == "0":
            return True
        else:
            warn("не понял выбор: %r" % ch)


def ui_main(preset_link=None):
    if preset_link:
        n = ui_new_link(preset_link)
        if n:
            ui_profile(n)

    while True:
        store = load_store()
        profs = list(store["profiles"].items())
        last = store.get("last")

        print()
        print(bold("== vlctl ==") + dim("  клиент vless:// поверх xray-core / sing-box"))
        if profs:
            print("\n  Сохранённые подключения:")
            width = max(len(n) for n, _ in profs)
            for i, (n, link) in enumerate(profs, 1):
                p = parse_link(link)
                mark = _c("32", " ←последнее") if n == last else ""
                print("   %2d) %-*s  %s%s" % (i, width, n, dim(describe(p)), mark))
        else:
            print("\n  " + dim("сохранённых подключений пока нет"))

        print("""
    n) Добавить новую ссылку
    i) Импортировать подписку (URL или файл)
    q) Выход""")

        default = "1" if profs else "n"
        if last and profs:
            default = str([n for n, _ in profs].index(last) + 1)
        ch = ask("Выбор", default)

        if ch in ("q", "Q", "0"):
            return 0
        if ch in ("n", "N"):
            n = ui_new_link()
            if n:
                ui_profile(n)
            continue
        if ch in ("i", "I"):
            src = ask("URL подписки или путь к файлу")
            try:
                import_subscription(src)
            except SystemExit:
                pass
            continue
        if ch.isdigit() and 1 <= int(ch) <= len(profs):
            ui_profile(profs[int(ch) - 1][0])
            continue
        warn("не понял выбор: %r" % ch)


# ---------------------------------------------------------------- команды CLI

def import_subscription(src):
    if re.match(r"^https?://", src):
        info("качаю подписку…")
        blob = http_get(src)
    else:
        with open(os.path.expanduser(src), "rb") as f:
            blob = f.read()

    text = blob.decode("utf-8", errors="replace").strip()
    if "vless://" not in text:
        pad = text + "=" * (-len(text) % 4)
        try:
            text = base64.b64decode(pad).decode("utf-8", errors="replace")
        except Exception:
            die("не похоже ни на список ссылок, ни на base64-подписку")

    links = [l.strip() for l in text.splitlines() if l.strip().startswith("vless://")]
    if not links:
        die("в подписке нет vless:// ссылок (другие протоколы vlctl не поддерживает)")

    added = 0
    for link in links:
        try:
            add_profile(link)
            added += 1
        except SystemExit:
            continue
    info("импортировано %d конфигов -> %s" % (added, STORE))
    return added


def cmd_up(a):
    target = a.target
    if getattr(a, "link_file", None):
        with open(a.link_file, "r", encoding="utf-8") as f:
            target = f.read().strip()
        try:
            os.unlink(a.link_file)
        except OSError:
            pass
    if not target:
        die("нужна ссылка vless:// или имя профиля")

    p = resolve(target)
    if target.startswith("vless://") and sys.stdin.isatty() and not getattr(a, "link_file", None):
        if target.strip() not in load_store()["profiles"].values():
            try:
                if confirm("Сохранить эту ссылку в профили?", True):
                    saved = add_profile(target, ask("Название", p["name"]))
                    info("сохранено: «%s»" % saved)
            except Abort:
                pass
    return connect(p, Opts.from_args(a))


def cmd_test(a):
    return check(resolve(a.target), Opts.from_args(a))


def cmd_config(a):
    p = resolve(a.target)
    if a.tun:
        sb = find_bin("sing-box")
        cfg = singbox_config(p, a.dns, modern=(singbox_version(sb) >= (1, 12)) if sb else True)
    else:
        cfg = xray_config(p, a.socks_port, a.http_port)
    print(json.dumps(cfg, ensure_ascii=False, indent=2))
    return 0


def cmd_save(a):
    saved = add_profile(a.link, a.name)
    info("сохранён профиль «%s»" % saved)
    return 0


def cmd_rename(a):
    store = load_store()
    if a.old not in store["profiles"]:
        die("нет профиля «%s»" % a.old)
    link = store["profiles"][a.old]
    fresh = unique_name(store["profiles"], a.new, link)
    store["profiles"] = {(fresh if k == a.old else k): v for k, v in store["profiles"].items()}
    if store.get("last") == a.old:
        store["last"] = fresh
    save_store(store)
    info("«%s» -> «%s»" % (a.old, fresh))
    return 0


def cmd_ls(a=None):
    store = load_store()
    profs = store["profiles"]
    if not profs:
        print("профилей нет (vlctl save <имя> <ссылка>, vlctl import <url> или просто vlctl)")
        return 0
    width = max(len(k) for k in profs)
    for name, link in profs.items():
        p = parse_link(link)
        mark = " ←последнее" if name == store.get("last") else ""
        print("%-*s  %-34s  %s%s" % (width, name, describe(p), p["name"], mark))
    return 0


def cmd_rm(a):
    store = load_store()
    if a.name not in store["profiles"]:
        die("нет профиля «%s»" % a.name)
    del store["profiles"][a.name]
    if store.get("last") == a.name:
        store["last"] = None
    save_store(store)
    info("удалён «%s»" % a.name)
    return 0


def cmd_import(a):
    import_subscription(a.source)
    return cmd_ls()


def cmd_install(a):
    install_core(sing_box=a.sing_box)
    return 0


def cmd_menu(a):
    return ui_main(getattr(a, "link", None))


def build_parser():
    ap = argparse.ArgumentParser(
        prog="vlctl",
        description="CLI-клиент для vless:// (xray-core / sing-box). Без аргументов — меню.")
    sub = ap.add_subparsers(dest="cmd")

    def common(sp):
        sp.add_argument("--socks-port", type=int, default=10808)
        sp.add_argument("--http-port", type=int, default=10809, help="0 — не поднимать HTTP-прокси")
        sp.add_argument("--dns", default="1.1.1.1", help="DNS для TUN-режима")
        sp.add_argument("-v", "--verbose", action="store_true")

    s = sub.add_parser("up", help="поднять подключение")
    s.add_argument("target", nargs="?", help="vless://... или имя профиля")
    s.add_argument("--tun", action="store_true", help="весь трафик системы через VPN (sing-box, root)")
    s.add_argument("--link-file", help=argparse.SUPPRESS)  # внутреннее: передача ссылки под sudo
    common(s)
    s.set_defaults(func=cmd_up)

    s = sub.add_parser("test", help="проверить конфиг и внешний IP")
    s.add_argument("target")
    common(s)
    s.set_defaults(func=cmd_test)

    s = sub.add_parser("config", help="напечатать JSON-конфиг ядра")
    s.add_argument("target")
    s.add_argument("--tun", action="store_true")
    common(s)
    s.set_defaults(func=cmd_config)

    s = sub.add_parser("save", help="сохранить профиль")
    s.add_argument("name")
    s.add_argument("link")
    s.set_defaults(func=cmd_save)

    s = sub.add_parser("rename", help="переименовать профиль")
    s.add_argument("old")
    s.add_argument("new")
    s.set_defaults(func=cmd_rename)

    s = sub.add_parser("import", help="импортировать подписку")
    s.add_argument("source", help="URL или файл")
    s.set_defaults(func=cmd_import)

    s = sub.add_parser("ls", help="список профилей")
    s.set_defaults(func=cmd_ls)

    s = sub.add_parser("rm", help="удалить профиль")
    s.add_argument("name")
    s.set_defaults(func=cmd_rm)

    s = sub.add_parser("install", help="скачать ядро в ~/.local/share/vlctl/bin")
    s.add_argument("--sing-box", action="store_true", help="ставить sing-box (для --tun) вместо xray")
    s.set_defaults(func=cmd_install)

    return ap


def main():
    argv = sys.argv[1:]

    # Без аргументов или сразу со ссылкой — интерактивное меню.
    if not argv or (len(argv) == 1 and argv[0].startswith("vless://")):
        if not sys.stdin.isatty():
            build_parser().print_help()
            return 2
        try:
            return ui_main(argv[0] if argv else None)
        except Abort:
            print()
            return 130

    a = build_parser().parse_args(argv)
    if not getattr(a, "func", None):
        build_parser().print_help()
        return 2
    try:
        return a.func(a) or 0
    except Abort:
        return 130


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
