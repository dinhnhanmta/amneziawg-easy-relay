# AmneziaWG Easy + AWG 3.1 relay

Bộ cài một lệnh cho **Ubuntu 24.04 amd64**, chạy bằng **root**, không hỏi mật khẩu cài đặt hoặc menu tương tác.

```text
Client AWG → relay:2445/UDP → tunnel AWG 3.1 → OUT → AmneziaWG Easy → Internet
```

AWG Easy quản lý khách trên OUT. Relay chỉ chuyển tiếp UDP; không cần panel, database hoặc LucX. Hai lớp AWG dùng khóa và tham số độc lập.

## Cài trên hai VPS mới

Cần VPS có TUN (`/dev/net/tun`), systemd, Internet/APT, `curl` và Python 3. Đăng nhập root trước. Bộ cài không cấu hình đăng nhập SSH hay bỏ mật khẩu SSH/sudo. Nếu dùng tài khoản thường, chỉ dùng `sudo -n bash ...` khi đã có sudo không mật khẩu.

**1. Trên OUT**, thay `OUT_IP` và `RELAY_IP` bằng IPv4 hoặc tên miền của bạn, rồi chạy một dòng:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/dinhnhanmta/amneziawg-easy-relay/main/install.sh) --role out --out-host OUT_IP --relay-host RELAY_IP
```

**2. Trên relay**, dán nguyên lệnh một dòng có `--role relay --pair ...` được OUT in ra. Không cần gõ mật khẩu hoặc nhập từng khóa. Chỉ chuyển token qua kênh riêng giữa hai máy.

**3. Mở panel** từ máy cá nhân:

```bash
ssh -L 51821:127.0.0.1:51821 root@OUT_IP
```

Truy cập `http://127.0.0.1:51821`. Trên OUT, xem mật khẩu quản trị tự sinh bằng `cat /opt/amnezia-easy-relay/panel-password.txt`. Đây là mật khẩu đăng nhập panel; không có bước nhập mật khẩu khi cài.

Tạo khách và tải file/QR từ panel. Endpoint của khách tự trỏ về **RELAY_IP:2445**. Cần ứng dụng tương thích AmneziaWG legacy cho kết nối client; lớp 3.1 chỉ nằm giữa hai VPS.

## Firewall và DNS

Firewall của nhà cung cấp cần cho phép:

| VPS | Inbound |
| --- | --- |
| Relay | UDP 2445 từ client; SSH từ mạng quản trị |
| OUT | UDP 34431 từ IP relay; SSH từ mạng quản trị |

Panel chỉ publish lên `127.0.0.1:51821`, không cần mở TCP 51821 công khai. Container AWG Easy publish UDP 2445 trên host OUT để nhận gói từ tunnel; có thể giữ cổng này đóng ở firewall nhà cung cấp để tránh client đi trực tiếp vào OUT.

Tên miền phải có bản ghi A đúng IPv4, dùng DNS only nếu qua Cloudflare. Relay cập nhật endpoint OUT từ DNS mỗi phút; tốc độ nhận IP mới còn phụ thuộc cache/TTL. Client phân giải lại DNS relay theo hành vi của ứng dụng; có thể cần tắt/bật VPN khi thay relay.

Installer thêm các rule cần thiết vào iptables host và lặp lại mỗi phút; không flush firewall hay bật/tắt UFW. Nó không thay được firewall trong dashboard nhà cung cấp. Chỉ dùng lần cài đầu trên VPS mới, vì Docker/APT và luật mạng ảnh hưởng hệ thống máy.

## Khóa và chạy lại

- Mỗi cặp VPS tự sinh khóa mới, không có khóa riêng cố định trên GitHub.
- Token ghép chứa **private key relay và khóa Header Protection**, được mã hóa biểu diễn bằng base64, **không phải mã hóa bảo mật**. Không đăng token lên GitHub/chat công khai. Dùng `--pair-file /root/relay-pair.txt` thay `--pair` nếu muốn tránh lưu token trong shell history.
- OUT lưu token tại `/opt/amnezia-easy-relay/relay-pair.txt`, dữ liệu khách tại thư mục `easy/`, cấu hình và image digest trong `state.json`. Thư mục gốc có mode 700, file chứa bí mật có mode 600.
- Chạy lại đúng lệnh cũ sẽ giữ khóa, dữ liệu, mật khẩu và image digest. Tham số khác hoặc container không do installer quản lý sẽ bị từ chối; không tự tiếp quản hệ thống cũ.
- Bind mount **thư mục** backhaul, không mount từng file; thay file bằng thao tác atomic không gây giữ inode cũ. Rerun không thay cấu hình của container đang chạy bằng tham số mới.

## Kiểm tra, khôi phục engine và backup

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/dinhnhanmta/amneziawg-easy-relay/main/install.sh) --role status
```

Kiểm tra engine backhaul, IPv4 forwarding, timer; OUT kiểm tra interface AWG Easy và HTTP panel, relay kiểm tra ping qua tunnel. Kết quả này chưa chứng minh Internet/DNS/UDP từ client hoặc tự phục hồi sau reboot.

```bash
journalctl -u awge-maintain.service -n 50 --no-pager
docker logs --tail 50 awge-backhaul
docker logs --tail 50 amnezia-wg-easy  # chỉ có trên OUT
```

Timer chạy mỗi phút, restart container khi engine/interface cục bộ không đáp ứng, cập nhật DNS và áp lại firewall. Process AWG chạy foreground được giám sát: engine chết thì container thoát để Docker restart; không dùng `tail -f /dev/null`. Mất kết nối mạng chỉ ghi log, không restart lặp vì peer tạm offline. Có giới hạn xoay log Docker; không tự tạo swap, đặt giới hạn RAM hoặc reboot.

Tạo backup trên từng máy:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/dinhnhanmta/amneziawg-easy-relay/main/install.sh) --role backup
```

Backup nằm trong `/root/awge-ROLE-TIMESTAMP.tar.gz`, chứa toàn bộ `/opt/amnezia-easy-relay` cùng khóa và dữ liệu; giữ riêng. OUT tạm dừng AWG Easy trong lúc backup, rồi khởi động lại dù tar báo lỗi. Tải backup ra khỏi VPS sau khi thay đổi khách.

Khôi phục thủ công trên VPS mới cùng vai trò: dùng root tạo `/opt/amnezia-easy-relay` mode 700, giải nén **backup của chính bạn** vào đó rồi chạy lại lệnh cài cũ. Installer cài lại phụ thuộc khi cần, tải lại các image digest đã lưu, dựng container và systemd units từ state. Khi đổi IP OUT, cập nhật DNS A cũ trước để relay vẫn dùng cùng tên miền. Khi dùng IP literal hoặc thay endpoint, cần chỉnh state/token và cấu hình liên quan có chủ đích; chưa có lệnh tự chuyển IP. Không khôi phục cùng identity lên hai VPS hoạt động đồng thời.

AWG Easy cũ cần import bản backup JSON đầy đủ qua UI để giữ khóa server, tham số AWG và các peer cũ. Bộ cài không lấy hay publish dữ liệu khách từ máy cá nhân và không tự chuyển hệ thống đang chạy.

## MTU và MSS

Mặc định backhaul MTU **1380**, client MTU **1280**, giữ khoảng trống cho lớp VPN bên trong trên đường truyền VPS MTU 1500. Client route cả IPv4/IPv6 vào VPN nhưng bản cài này chỉ cung cấp Internet IPv4; lưu lượng IPv6 được chặn do không có peer IPv6 tương ứng, không có egress IPv6. Cần kiểm tra bằng client thật.

Nếu đường truyền MTU thấp, có thể đặt lúc cài OUT `--mtu 1280 --client-mtu 1180`; mức client dưới 1280 chỉ phù hợp thử nghiệm IPv4, tùy hỗ trợ của ứng dụng. Không tự giảm MTU trên hệ thống đang chạy.

MSS mặc định **tắt**. Tùy chọn `--mss 1100` cài rule TCPMSS trong PostUp/PostDown của AWG Easy, tồn tại sau reboot/container restart. MSS chỉ áp dụng TCP, không giải quyết gói UDP lớn. Test download, upload, QUIC/UDP và PMTU trước khi kết luận nhanh hơn.

## Phiên bản và phạm vi kiểm thử

- Backhaul: `amneziavpn/amneziawg-go:3.1.20260828`, sau pull được ghi cố định theo digest.
- AWG Easy: image upstream `ghcr.io/w0rng/amnezia-wg-easy:latest` ở lần cài đầu; ghi digest để chạy lại/khôi phục không tự nâng phiên bản.
- Entry point kiểm tra SHA256 của `installer.py` trước khi chạy. Đây là kiểm tra khớp phiên bản, không thay thế việc tin cậy repo/HTTPS.
- Unit tests kiểm tra token, chống chèn hostname, cấu hình, retry giữ identity và logic kiểm tra lỗi. GitHub Actions kiểm tra Bash, Python và chạy container OUT thực tế trên Ubuntu runner nếu có quyền TUN/Docker.
- **Chưa chứng nhận chạy đầy đủ trên hai VPS hoặc điện thoại.** Bước tiếp theo là test VPS mới, client Internet/DNS/TCP/UDP, firewall nhà cung cấp và reboot từng máy.

Upstream: [AmneziaWG Go](https://github.com/amnezia-vpn/amneziawg-go), [AmneziaWG Easy](https://github.com/w0rng/amnezia-wg-easy), [tham số AWG](https://docs.amnezia.org/documentation/amnezia-wg/). Mã installer mới dùng MIT; image upstream giữ giấy phép riêng của dự án tương ứng.
