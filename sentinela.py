import requests
from urllib.parse import urlparse

TOR_PROXIES = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050"
}


G = "\033[38;5;78m"
W = "\033[38;5;252m"
D = "\033[38;5;243m"
Y = "\033[38;5;221m"
R = "\033[38;5;203m"
RESET = "\033[0m"

HEADERS = {
    "Content-Security-Policy": "CSP",
    "Strict-Transport-Security": "HSTS",
    "X-Frame-Options": "X-Frame-Options",
    "X-Content-Type-Options": "X-Content-Type",
    "Referrer-Policy": "Referrer-Policy"
}

LOGO = f"""
{G}             ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣤⣾⣼⢀⣆⣀⠀⡆⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢠⣠⣶⣽⣸⣯⣼⣽⣿⣼⣿⣧⣿⣷⢾⣷⣤⡎⠀⢠⠂⠀⠀⠀
⠀⠀⠀⡀⢤⣜⢯⣼⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡳⢮⡵⢓⡔⡀⡀⠀
⠀⠀⢢⡸⣫⣿⣿⡿⢋⣵⠟⠋⢁⣀⣀⡀⠉⠛⢿⣿⣿⣿⣿⣿⣷⣿⣵⢣⠃
⠀⢈⣮⣟⣿⢻⡏⠀⣼⡏⠀⣰⡟⠋⠉⠛⢷⣄⠀⢻⡾⡻⣿⣿⣿⣽⣗⡯⠋
⠈⣾⣿⠫⠄⢸⡇⠀⢻⣧⠀⠘⠟⢛⣷⠀⠈⣿⠀⢈⣿⠎⠈⣿⢿⣷⣿⠶⠂
⠟⡹⢇⢳⢆⠈⢿⣆⠀⠙⠿⠶⠶⠿⠋⢀⣼⡟⠀⡼⠋⢀⣼⣿⢷⢥⡟⠀⠀
⠀⣕⣭⣚⠬⣑⣂⠽⠿⣶⣤⣤⣤⣤⣶⠟⢋⢤⣊⣀⣴⣿⠛⡻⡜⡼⠀⠀⠀
⠀⠀⣍⣩⣖⠄⡘⠋⠿⢲⠶⢷⡿⡴⡶⡴⢶⣟⢿⢪⢳⠓⠁⠐⡱⠃⠀⠀⠀
⠀⠀⠁⠈⠑⠮⡓⠬⣁⠀⠁⠀⡁⠏⠿⠘⠘⠺⡎⠁⡹⠔⠁⠔⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠐⠂⠤⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀'

        S E N T I N E L A

      
      BY: https://github.com/Beliroth
         
"""

def validate_target(target):
    parsed = urlparse(target)

    return (
        parsed.scheme == "https"
        and parsed.hostname is not None
        and not parsed.username
        and not parsed.password
    )



def verify_tor(session):
    try:
        response = session.get(
            "https://check.torproject.org/api/ip",
            timeout=20
        )

        response.raise_for_status()
        result = response.json()

        return result.get("IsTor") is True

    except (requests.exceptions.RequestException, ValueError):
        return False


def analyze(target):
    try:
        with requests.Session() as session:
            session.trust_env = False
            session.proxies.update(TOR_PROXIES)

            if not verify_tor(session):
                print(f"\n{R}TOR VERIFICATION FAILED.{RESET}")
                print(f"{Y}Analysis cancelled. No target request was sent.{RESET}\n")
                return

            print(f"\n{G}TOR CONNECTION VERIFIED.{RESET}")

            response = session.get(
                target,
                timeout=30,
                allow_redirects=True,
                headers={
                    "User-Agent": "Mozilla/5.0"
                }
            )

        if urlparse(response.url).scheme != "https":
            print(f"\n{R}Final destination is not HTTPS.{RESET}")
            return

        print(f"\n{D}TARGET{RESET}")
        print(f"  {W}{urlparse(response.url).hostname}{RESET}")
        print(f"  {D}HTTP RESPONSE{RESET}  {W}{response.status_code}{RESET}")

        print(f"\n{G}SECURITY INSPECTION{RESET}\n")

        detected = 0
        missing = 0

        for header, label in HEADERS.items():
            value = response.headers.get(header)

            if value and value.strip():
                status = f"{G}Detected{RESET}"
                detected += 1
            else:
                status = f"{Y}Not detected{RESET}"
                missing += 1

            print(f"  {W}{label:<18}{RESET} {status}")

        print(f"\n{D}INSPECTION SUMMARY{RESET}")
        print(f"  Headers inspected  {W}{len(HEADERS)}{RESET}")
        print(f"  Detected           {G}{detected}{RESET}")
        print(f"  Not detected       {Y}{missing}{RESET}")

        print(f"\n{G}Inspection completed.{RESET}\n")

    except requests.exceptions.SSLError:
        print(f"\n{R}TLS verification failed.{RESET}")

    except requests.exceptions.Timeout:
        print(f"\n{R}Connection timed out.{RESET}")

    except requests.exceptions.RequestException:
        print(f"\n{R}Connection failed. Check Tor.{RESET}")


def main():
    print(LOGO)
    print(f"{D}{'─' * 43}{RESET}")
    print(f"{D}HTTP SECURITY HEADER ANALYZER · v1.0{RESET}")
    print(f"{D}{'─' * 43}{RESET}")

    target = input(f"\n{G}TARGET {D}>{RESET} ").strip()

    if not validate_target(target):
        print(f"\n{R}Invalid HTTPS address.{RESET}")
        return

    analyze(target)


if __name__ == "__main__":
    main()
