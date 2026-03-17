import socket
import ssl
import requests
import whois

def scan_domain(domain):
    result = {}

    # ---------------- IP Address ----------------
    try:
        ip = socket.gethostbyname(domain)
        result["IP Address"] = ip
    except:
        result["IP Address"] = "Unable to resolve"

    # ---------------- SSL Certificate ----------------
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.socket(), server_hostname=domain
        ) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()

        result["SSL Issuer"] = dict(cert["issuer"])
        result["SSL Valid From"] = cert["notBefore"]
        result["SSL Valid Till"] = cert["notAfter"]
    except:
        result["SSL"] = "No SSL / Error fetching certificate"

    # ---------------- HTTP Headers ----------------
    try:
        r = requests.get(f"https://{domain}", timeout=5)
        headers = r.headers

        security_headers = {
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options")
        }

        result["Security Headers"] = security_headers
    except:
        result["Security Headers"] = "Unable to fetch headers"

    # ---------------- WHOIS ----------------
    try:
        w = whois.whois(domain)
        result["Domain Registrar"] = w.registrar
        result["Creation Date"] = str(w.creation_date)
        result["Expiry Date"] = str(w.expiration_date)
    except:
        result["WHOIS"] = "WHOIS lookup failed"

    return result
