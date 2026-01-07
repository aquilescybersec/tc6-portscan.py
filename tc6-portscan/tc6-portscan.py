import socket
import threading
import argparse
from queue import Queue
from rich.console import Console
from rich.table import Table
from rich.theme import Theme

# ================== SERVIÇOS COMUNS ==================
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 143: "imap",
    443: "https", 3306: "mysql", 5432: "postgresql",
    6379: "redis", 8080: "http-alt"
}

# ================== TEMAS ==================
THEMES = {
    "neon": Theme({
        "open": "bold bright_green",
        "port": "bright_cyan",
        "service": "bright_magenta",
        "version": "bright_yellow"
    }),
    "dark": Theme({
        "open": "bold green",
        "port": "cyan",
        "service": "magenta",
        "version": "yellow"
    }),
    "red": Theme({
        "open": "bold red",
        "port": "bright_white",
        "service": "bright_red",
        "version": "bright_yellow"
    }),
    "blue": Theme({
        "open": "bold bright_blue",
        "port": "white",
        "service": "cyan",
        "version": "bright_green"
    })
}

# ================== ARGUMENTOS ==================
parser = argparse.ArgumentParser(
    description="Python Port Scanner (RustScan-style)"
)

parser.add_argument("-t", "--target", required=True, help="Target host")
parser.add_argument("-p", "--ports", default="1-65535",
                    help="Port range (1-1000 or 80,443)")
parser.add_argument("-T", "--threads", type=int, default=400)
parser.add_argument("--timeout", type=float, default=1)
parser.add_argument("--theme", choices=THEMES.keys(), default="neon")

args = parser.parse_args()

console = Console(theme=THEMES[args.theme])
queue = Queue()
results = []

# ================== FUNÇÕES ==================
def parse_ports(port_arg):
    ports = set()
    for part in port_arg.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def grab_banner(sock):
    try:
        sock.sendall(b"\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner if banner else "unknown"
    except:
        return "unknown"

def scan_port(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(args.timeout)
        if sock.connect_ex((args.target, port)) == 0:
            service = COMMON_SERVICES.get(port, "unknown")
            banner = grab_banner(sock)
            results.append((port, service, banner))
        sock.close()
    except:
        pass

def worker():
    while not queue.empty():
        port = queue.get()
        scan_port(port)
        queue.task_done()

# ================== EXECUÇÃO ==================
def main():
    ports = parse_ports(args.ports)

    console.print(f"\n[bold cyan]▶ Target:[/] {args.target}")
    console.print(f"[bold cyan]▶ Ports:[/] {args.ports}")
    console.print(f"[bold cyan]▶ Threads:[/] {args.threads}")
    console.print(f"[bold cyan]▶ Theme:[/] {args.theme}\n")

    for port in ports:
        queue.put(port)

    for _ in range(args.threads):
        threading.Thread(target=worker, daemon=True).start()

    queue.join()
    show_results()

def show_results():
    table = Table(title="Port Scan Results", header_style="bold blue")
    table.add_column("PORT", style="port", justify="right")
    table.add_column("STATE", style="open")
    table.add_column("SERVICE", style="service")
    table.add_column("VERSION / BANNER", style="version")

    for port, service, banner in sorted(results):
        table.add_row(str(port), "OPEN", service, banner)

    console.print(table)

if __name__ == "__main__":
    main()

