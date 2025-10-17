#!/usr/bin/env python3
import sys, threading, requests, queue, time

SUBDOMAIN_FILE = "subdomains.txt"
OUTPUT_FILE = "discovered_subdomains.txt"
THREAD_COUNT = 30
REQUEST_TIMEOUT = 5.0
PROBE_HTTPS = True
RATE_LIMIT_DELAY = 0.0
USER_AGENT = "Inlighn-SubEnum/1.0 (+https://example.local)"

write_lock = threading.Lock()
q = queue.Queue()
discovered = []
session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})

def check_subdomain(domain, sub):
    host = f"{sub}.{domain}".strip('.')
    urls = [f"http://{host}"]
    if PROBE_HTTPS:
        urls.append(f"https://{host}")
    for url in urls:
        try:
            resp = session.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=False)
            if resp.status_code in (405, 501):
                resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=False)
            if resp.status_code < 400:
                return (url, resp.status_code)
            if resp.status_code in (401, 403, 400, 404):
                return (url, resp.status_code)
        except requests.exceptions.SSLError:
            if url.startswith("https://"):
                return (url + " (SSL error)", "SSL")
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
            pass
        except Exception:
            pass
    return None

def worker(domain):
    while True:
        try:
            sub = q.get_nowait()
        except queue.Empty:
            return
        result = check_subdomain(domain, sub)
        if RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY)
        if result:
            url, status = result
            entry = f"{sub}.{domain}\t{url}\t{status}"
            with write_lock:
                with open(OUTPUT_FILE, "a", encoding="utf-8") as out:
                    out.write(entry + "\n")
                discovered.append(entry)
                print("[+] Found:", entry)
        q.task_done()

def load_subdomains(filename):
    subs = []
    try:
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                label = line.split('.')[0]
                subs.append(label)
    except FileNotFoundError:
        print(f"ERROR: subdomain file '{filename}' not found.")
        sys.exit(1)
    return subs

def clear_output_file():
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(f"# Discovered subdomains for run on {time.ctime()}\n")

def main():
    if len(sys.argv) != 2:
        print("Usage: python subenum_threaded.py target.com")
        sys.exit(1)
    domain = sys.argv[1].strip().lower()
    if "/" in domain or " " in domain:
        print("ERROR: please provide a bare domain like 'example.com'")
        sys.exit(1)

    subs = load_subdomains(SUBDOMAIN_FILE)
    if not subs:
        print("No subdomains loaded from", SUBDOMAIN_FILE)
        sys.exit(1)

    print(f"Target domain: {domain}")
    print(f"Loaded {len(subs)} candidates from {SUBDOMAIN_FILE}")
    print(f"Using {THREAD_COUNT} threads, timeout={REQUEST_TIMEOUT}s, https_probe={PROBE_HTTPS}")

    clear_output_file()

    for s in subs:
        q.put(s)

    threads = []
    for i in range(min(THREAD_COUNT, q.qsize())):
        t = threading.Thread(target=worker, args=(domain,), daemon=True)
        t.start()
        threads.append(t)

    try:
        q.join()
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
        sys.exit(1)

    print("\nScan complete.")
    print(f"Discovered {len(discovered)} reachable subdomains (written to {OUTPUT_FILE})")
    for d in discovered:
        print("  -", d)

if __name__ == "__main__":
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass
    main()


