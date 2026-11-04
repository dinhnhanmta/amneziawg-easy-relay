# AmneziaWG Easy relay

## Relay NAT kernel: lựa chọn nhẹ CPU khi UDP giữa hai VPS hoạt động

```text
Client AWG → relay:2445/UDP [DNAT + SNAT kernel] → OUT:2445/UDP [AWG Easy] → Internet
```

Relay chuyển tiếp gói AWG đã mã hóa, **không bọc thêm một VPN giữa hai VPS**. AWG Easy, khóa và quản lý user nằm trên OUT. Chuyển panel sang relay không tự làm VPN nhanh hơn; kết thúc AWG trên relay còn tốn CPU mã hóa/giải mã tại đó. NAT tránh thêm process relay trong userspace. Đã tham khảo [Realm](https://github.com/zhboner/realm) và [Netfilter NAT](https://netfilter.org/projects/nftables/manpage.html); bản này dùng iptables kernel trực tiếp.

Nếu OUT đã có AWG Easy hoạt động và đang nghe UDP 2445, chạy **một dòng trên relay Ubuntu 24.04**, thay `OUT_IP` bằng IPv4 hoặc tên miền OUT:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/dinhnhanmta/amneziawg-easy-relay/main/direct.sh) --out-host OUT_IP --listen-port 2445 --out-port 2445
```

Cần đăng nhập root; không hỏi mật khẩu cài, không cài Docker trên relay. Bộ cài tự thêm các gói iptables/iproute2/procps nếu thiếu. Nó không thay mật khẩu SSH/sudo hoặc mật khẩu panel. Trên AWG Easy, endpoint xuất cho client phải là `RELAY_IP:2445`. Giữ panel HTTPS trên OUT như hướng dẫn bên dưới. Muốn thử song song với hệ thống khác, chọn `--listen-port 2447` và sửa cổng endpoint trong profile thử tương ứng.

Firewall nhà cung cấp cần cho phép relay UDP 2445 từ client và OUT UDP 2445 từ IP relay. Gói client vẫn được AWG mã hóa xuyên suốt đến OUT; NAT không thêm lớp che giấu AWG 3.1 trên đoạn giữa VPS. Chọn đường tunnel bên dưới khi đường UDP trực tiếp bị chặn hoặc cần lớp bọc riêng giữa hai máy. Không dùng NAT này để chuyển lưu lượng chưa mã hóa nếu bạn cần bảo mật trên đoạn relay–OUT.

`awge-direct.timer` áp lại rule và phân giải DNS OUT mỗi phút, sau boot khoảng 20 giây. DNS lỗi giữ rule hiện tại. Khi đổi DNS thành công, các phiên NAT mới dùng IP mới; phiên UDP cũ có thể cần hết hạn conntrack hoặc tắt/bật VPN. Bộ cài dùng chain riêng, không flush firewall khác, không đổi default route của SSH. Khi cổng đã có DNAT cũ, rule mới đứng trước; gỡ bộ cài sẽ trả lại đường cũ nếu đường đó vẫn còn hoạt động. Chạy lại cùng lệnh giữ cấu hình; muốn đổi tham số phải gỡ rồi cài lại.

```bash
python3 /opt/awge-direct-relay/direct-relay.py --action status
journalctl -u awge-direct.service -n 30 --no-pager
# Gỡ riêng rule/timer NAT mới; giữ cấu hình lưu để kiểm tra/cài lại:
python3 /opt/awge-direct-relay/direct-relay.py --action remove
```

Kết quả thử thực tế trên một cặp VPS: điện thoại Wi-Fi từ khoảng **160/160 lên 275/215 Mbps** sau khi bỏ backhaul bọc thêm. Phép đo iperf riêng cho thấy CPU relay từ gần 95% xuống khoảng 3–8%; iperf đó dùng client chẩn đoán trên VPS, không tương đương Speedtest điện thoại. Đây là kết quả của đường truyền đã thử, không phải cam kết tốc độ cho VPS khác. MSS 1100 không được giữ vì thử trên cùng điện thoại không cải thiện đồng đều.

## Cài AWG Easy trên OUT và đường tunnel AWG 3.1 dự phòng

Các lệnh `install.sh` dưới đây dựng kiến trúc tunnel hai lớp cũ. Nếu dùng NAT trực tiếp, OUT vẫn có thể được cài bằng lệnh OUT này; sau đó relay chỉ cần lệnh `direct.sh` ở trên. Backhaul trên OUT khi đó không nằm trên đường dữ liệu của client.

Bộ cài một lệnh cho **Ubuntu 24.04 amd64**, chạy bằng **root**, không hỏi mật khẩu cài đặt hoặc menu tương tác.

```text
Client AWG → relay:2445/UDP → tunnel AWG 3.1 → OUT → AmneziaWG Easy → Internet
```

AWG Easy quản lý khách trên OUT. Relay chỉ chuyển tiếp UDP; không cần panel, database hoặc LucX. Hai lớp AWG dùng khóa và tham số độc lập.

### Cài đường tunnel trên hai VPS mới

Cần VPS có TUN (`/dev/net/tun`), systemd, Internet/APT, `curl` và Python 3. Đăng nhập root trước. Bộ cài không cấu hình đăng nhập SSH hay bỏ mật khẩu SSH/sudo. Nếu dùng tài khoản thường, chỉ dùng `sudo -n bash ...` khi đã có sudo không mật khẩu.

**1. Trên OUT**, thay `OUT_IP` và `RELAY_IP` bằng IPv4 hoặc tên miền của bạn, rồi chạy một dòng:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/dinhnhanmta/amneziawg-easy-relay/main/install.sh) --role out --out-host OUT_IP --relay-host RELAY_IP --public-ui
```

**2. Trên relay**, dán nguyên lệnh một dòng có `--role relay --pair ...` được OUT in ra. Không cần gõ mật khẩu hoặc nhập từng khóa. Chỉ chuyển token qua kênh riêng giữa hai máy.

**3. Mở panel trực tiếp tại `https://OUT_IP`** (TCP 443). Bộ cài tự tạo chứng chỉ tự ký có SAN khớp IP/tên miền OUT. Trình duyệt sẽ cảnh báo chứng chỉ: kiểm tra đúng địa chỉ VPS rồi chấp nhận chứng chỉ ở lần đầu. Mật khẩu quản trị tự sinh nằm trên OUT tại `/opt/amnezia-easy-relay/panel-password.txt`; xem bằng `cat` qua SSH. Không có bước nhập mật khẩu khi cài.

Nếu đã cài bản trước, chạy lại đúng lệnh OUT cũ và thêm **`--public-ui`** để bật HTTPS, giữ nguyên khóa, khách và mật khẩu. Cần cổng TCP 443 còn trống. Chứng chỉ có thời hạn 365 ngày, chưa tự gia hạn; cần thay chứng chỉ và restart `awge-panel-https` trước khi hết hạn. Nếu đã có tên miền/chứng chỉ tin cậy, có thể thay `ui/panel.crt` và `ui/panel.key` trong thư mục cài.

Nếu muốn panel chỉ truy cập qua SSH, bỏ `--public-ui` ở **lần cài đầu**, sau đó mở tunnel từ máy cá nhân:

```bash
ssh -L 51821:127.0.0.1:51821 root@OUT_IP
```

Truy cập `http://127.0.0.1:51821`. Truy cập `http://OUT_IP:51821` sẽ không hoạt động vì cổng HTTP backend chỉ mở trên localhost. Khi HTTPS đã bật, bỏ flag trong lần chạy sau không tự tắt HTTPS; cấu hình đã lưu được giữ nguyên.

Tạo khách và tải file/QR từ panel. Endpoint của khách tự trỏ về **RELAY_IP:2445**. Cần ứng dụng tương thích AmneziaWG legacy cho kết nối client; lớp 3.1 chỉ nằm giữa hai VPS.

## Firewall và DNS

Firewall của nhà cung cấp cần cho phép:

| VPS | Inbound |
| --- | --- |
| Relay | UDP 2445 từ client; SSH từ mạng quản trị |
| OUT | UDP 34431 từ IP relay; TCP 443 để truy cập panel HTTPS; SSH từ mạng quản trị |

Backend AWG Easy chỉ publish lên `127.0.0.1:51821`; khi có `--public-ui`, container Nginx chuyển tiếp HTTPS công khai trên TCP 443 tới backend này. Mật khẩu đăng nhập panel vẫn được yêu cầu. Không cần mở TCP 51821 công khai. Container AWG Easy publish UDP 2445 trên host OUT để nhận gói từ tunnel; có thể giữ cổng này đóng ở firewall nhà cung cấp để tránh client đi trực tiếp vào OUT.

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

Kiểm tra engine backhaul, IPv4 forwarding, timer; OUT kiểm tra interface AWG Easy, HTTP backend và HTTPS khi được bật, relay kiểm tra ping qua tunnel. HTTPS được kiểm tra bằng chứng chỉ đã lưu, không bỏ xác minh TLS. Kết quả này chưa chứng minh Internet/DNS/UDP từ client hoặc tự phục hồi sau reboot.

```bash
journalctl -u awge-maintain.service -n 50 --no-pager
docker logs --tail 50 awge-backhaul
docker logs --tail 50 amnezia-wg-easy  # chỉ có trên OUT
docker logs --tail 50 awge-panel-https  # nếu đã bật HTTPS
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

Mặc định backhaul MTU **1360**, client MTU **1280**. Phải tính cả lớp AWG 3.1: với S4=17, một gói đầy 1380 byte có thể cần ít nhất **1457 byte** trên IPv4 sau khi thêm IP/UDP, header và tag AWG. Đường truyền giữa hai VPS test chỉ cho phép **1456 byte**, nên mặc định cũ 1380 gây mất gói và làm TCP qua tunnel bị đứng. Mức 1360 để lại khoảng trống cho tuyến này; đường truyền khác vẫn cần đo PMTU thực tế.

Client route cả IPv4/IPv6 vào VPN nhưng bản cài này chỉ cung cấp Internet IPv4; lưu lượng IPv6 được chặn do không có peer IPv6 tương ứng, không có egress IPv6. Cần kiểm tra bằng client thật.

Nếu thay MTU đã lưu, phải đổi đồng bộ hai đầu và token ghép. Chỉ `docker start` không áp dụng command/MTU mới: installer tái tạo container backhaul do nó quản lý khi startup command thay đổi, giữ container cũ để rollback nếu engine mới không lên. Dữ liệu mount và khóa được giữ nguyên; có gián đoạn tunnel ngắn khi đổi container.

### Backhaul kernel khi relay yếu CPU

Mặc định vẫn dùng engine Go để chạy trên VPS mới có TUN. Nếu relay đã có **module AmneziaWG kernel tương thích AWG 3.1/Header Protection**, có thể thêm `--backhaul-engine kernel` vào lệnh cài relay. Chạy lại với `--backhaul-engine go` để trở về engine Go. Lựa chọn được lưu trong state, các lần chạy sau không tự đổi lại.

Đã thử kernel module `3.1.20260812` trên Ubuntu kernel `6.8.0-137-generic`: tạo tunnel với khóa thử riêng, xác nhận handshake thật với OUT Go và đo hai chiều trước khi chuyển relay. Header Protection, padding, khóa production, endpoint và AWG Easy trên OUT được giữ nguyên. Container vẫn quản lý vòng đời interface kernel và watchdog kiểm tra bằng `awg show`; không còn tiến trình `amneziawg-go` cho backhaul kernel này.

Installer **không tự build, nâng cấp hoặc thay module kernel**. Khi restore state dùng kernel lên VPS mới, cần cài module tương thích trước; không suy ra hỗ trợ 3.1 chỉ từ việc `ip link add ... type amneziawg` thành công. Tham khảo [module chính thức](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module). Tốc độ phụ thuộc CPU, đường mạng, client và điểm đo, không có cam kết 250/250 Mbps.

Nếu đường truyền MTU thấp, có thể đặt lúc cài OUT `--mtu 1280 --client-mtu 1180`; mức client dưới 1280 chỉ phù hợp thử nghiệm IPv4, tùy hỗ trợ của ứng dụng. Không tự giảm MTU trên hệ thống đang chạy.

MSS mặc định **tắt**. Tùy chọn `--mss 1100` cài rule TCPMSS trong PostUp/PostDown của AWG Easy, tồn tại sau reboot/container restart. MSS chỉ áp dụng TCP, không giải quyết gói UDP lớn. Test download, upload, QUIC/UDP và PMTU trước khi kết luận nhanh hơn.

## Phiên bản và phạm vi kiểm thử

- Backhaul: `amneziavpn/amneziawg-go:3.1.20260828`, sau pull được ghi cố định theo digest.
- AWG Easy: image upstream `ghcr.io/w0rng/amnezia-wg-easy:latest` ở lần cài đầu; ghi digest để chạy lại/khôi phục không tự nâng phiên bản.
- HTTPS proxy tùy chọn: `nginx:stable-alpine`, cũng ghi cố định digest sau lần pull đầu.
- Entry point kiểm tra SHA256 của `installer.py` trước khi chạy. Đây là kiểm tra khớp phiên bản, không thay thế việc tin cậy repo/HTTPS.
- Unit tests kiểm tra token, chống chèn hostname, cấu hình, retry giữ identity và logic kiểm tra lỗi. GitHub Actions kiểm tra Bash, Python và chạy container OUT thực tế trên Ubuntu runner nếu có quyền TUN/Docker.
- **Chưa chứng nhận chạy đầy đủ trên hai VPS hoặc điện thoại.** Bước tiếp theo là test VPS mới, client Internet/DNS/TCP/UDP, firewall nhà cung cấp và reboot từng máy.

Upstream: [AmneziaWG Go](https://github.com/amnezia-vpn/amneziawg-go), [AmneziaWG Easy](https://github.com/w0rng/amnezia-wg-easy), [tham số AWG](https://docs.amnezia.org/documentation/amnezia-wg/). Mã installer mới dùng MIT; image upstream giữ giấy phép riêng của dự án tương ứng.
