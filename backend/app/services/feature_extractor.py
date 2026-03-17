"""
Feature extraction engine.

Extracts 30 numerical features from a URL that match the columns
the SVM model was trained on.  Each feature returns one of: -1, 0, 1.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import time
from typing import Any

import requests
from bs4 import BeautifulSoup
import whois


# ---------------------------------------------------------------------------
# Column order must match the training dataset exactly
# ---------------------------------------------------------------------------
FEATURE_COLUMNS: list[str] = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "Domain_registeration_length",
    "Favicon",
    "port",
    "HTTPS_token",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Abnormal_URL",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWidnow",
    "Iframe",
    "age_of_domain",
    "DNSRecord",
    "web_traffic",
    "Page_Rank",
    "Google_Index",
    "Links_pointing_to_page",
    "Statistical_report",
]

_SHORTENERS = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|"
    r"cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|"
    r"snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|"
    r"fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|"
    r"bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|"
    r"twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|"
    r"scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|link\.zip\.net"
)

_SUSPICIOUS_IPS = re.compile(
    r"146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|"
    r"78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|"
    r"83\.125\.22\.219|46\.242\.145\.98|107\.151\.148\.44|107\.151\.148\.107|"
    r"64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|"
    r"119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|"
    r"118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|"
    r"175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|"
    r"103\.232\.215\.140|69\.172\.201\.153|216\.218\.185\.162|54\.225\.104\.146|"
    r"103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|"
    r"62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|"
    r"34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|"
    r"192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|"
    r"52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|216\.38\.62\.18|"
    r"104\.130\.124\.96|47\.89\.58\.141|54\.86\.225\.156|54\.82\.156\.19|"
    r"37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42"
)

_SUSPICIOUS_DOMAINS = re.compile(
    r"at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|"
    r"sweddy\.com|myjino\.ru|96\.lt|ow\.ly"
)

_REQUEST_TIMEOUT = 8  # seconds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fetch(url: str) -> tuple[requests.Response | None, BeautifulSoup | None]:
    """Return (response, soup) or (None, None) on failure."""
    try:
        response = requests.get(url, timeout=_REQUEST_TIMEOUT, allow_redirects=True)
        soup = BeautifulSoup(response.text, "html.parser")
        return response, soup
    except Exception:
        return None, None


def _extract_domain(url: str) -> str:
    match = re.findall(r"://([^/]+)/?", url)
    if not match:
        return url
    domain = match[0]
    return domain.replace("www.", "")


def _whois_safe(domain: str) -> Any:
    try:
        return whois.whois(domain)
    except Exception:
        return None


def _global_rank(domain: str) -> int:
    try:
        resp = requests.post(
            "https://checkpagerank.net/",
            data={"name": domain},
            timeout=_REQUEST_TIMEOUT,
        )
        matches = re.findall(r"Global Rank: ([0-9]+)", resp.text)
        return int(matches[0]) if matches else -1
    except Exception:
        return -1


# ---------------------------------------------------------------------------
# Individual feature functions
# ---------------------------------------------------------------------------

def _having_ip_address(url: str) -> int:
    try:
        ipaddress.ip_address(url)
        return -1
    except ValueError:
        return 1


def _url_length(url: str) -> int:
    if len(url) < 54:
        return 1
    if len(url) <= 75:
        return 0
    return -1


def _shortening_service(url: str) -> int:
    return -1 if _SHORTENERS.search(url) else 1


def _having_at_symbol(url: str) -> int:
    return -1 if "@" in url else 1


def _double_slash_redirecting(url: str) -> int:
    return -1 if url.rfind("//") > 6 else 1


def _prefix_suffix(url: str) -> int:
    return -1 if re.search(r"https?://[^\-]+-[^\-]+/", url) else 1


def _having_sub_domain(url: str) -> int:
    domain_part = url
    if _having_ip_address(url) == -1:
        m = re.search(
            r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])|"
            r"(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}",
            url,
        )
        if m:
            domain_part = url[m.end():]
    dots = re.findall(r"\.", domain_part)
    if len(dots) <= 3:
        return 1
    if len(dots) == 4:
        return 0
    return -1


def _ssl_final_state(url: str) -> int:
    """Check HTTPS presence as a proxy for valid SSL."""
    return 1 if url.startswith("https://") else -1


def _domain_reg_length(whois_data: Any) -> int:
    if whois_data is None:
        return -1
    try:
        exp = str(whois_data.expiration_date)
        today = time.strftime("%Y-%m-%d")
        exp_year = int(exp.split()[0].split("-")[0])
        today_year = int(today.split("-")[0])
        return 1 if (exp_year - today_year) >= 1 else -1
    except Exception:
        return -1


def _favicon(soup: BeautifulSoup | None, url: str, domain: str) -> int:
    if soup is None:
        return -1
    for link in soup.find_all("link", href=True):
        href = link["href"]
        dots = re.findall(r"\.", href)
        if url in href or len(dots) == 1 or domain in href:
            return 1
        return -1
    return 1


def _port(domain: str) -> int:
    parts = domain.split(":")
    return -1 if len(parts) > 1 and parts[1] else 1


def _https_token(url: str) -> int:
    return 1 if url.startswith("https://") else -1


def _request_url(url: str, soup: BeautifulSoup | None, domain: str) -> int:
    if soup is None:
        return -1
    total = 0
    internal = 0
    for tag, attr in [("img", "src"), ("audio", "src"), ("embed", "src"), ("iframe", "src")]:
        for el in soup.find_all(tag, **{attr: True}):
            src = el[attr]
            total += 1
            if url in src or domain in src or len(re.findall(r"\.", src)) == 1:
                internal += 1
    if total == 0:
        return 1
    pct = internal / total * 100
    if pct < 22:
        return 1
    if pct < 61:
        return 0
    return -1


def _url_of_anchor(url: str, soup: BeautifulSoup | None, domain: str) -> int:
    if soup is None:
        return -1
    total = 0
    unsafe = 0
    for a in soup.find_all("a", href=True):
        href = a["href"]
        total += 1
        if "#" in href or "javascript" in href.lower() or "mailto" in href.lower() or (url not in href and domain not in href):
            unsafe += 1
    if total == 0:
        return 1
    pct = unsafe / total * 100
    if pct < 31:
        return 1
    if pct < 67:
        return 0
    return -1


def _links_in_tags(url: str, soup: BeautifulSoup | None, domain: str) -> int:
    if soup is None:
        return -1
    total = 0
    internal = 0
    for tag, attr in [("link", "href"), ("script", "src")]:
        for el in soup.find_all(tag, **{attr: True}):
            src = el[attr]
            total += 1
            if url in src or domain in src or len(re.findall(r"\.", src)) == 1:
                internal += 1
    if total == 0:
        return 1
    pct = internal / total * 100
    if pct < 17:
        return 1
    if pct < 81:
        return 0
    return -1


def _sfh(url: str, soup: BeautifulSoup | None, domain: str) -> int:
    if soup is None:
        return -1
    for form in soup.find_all("form", action=True):
        action = form["action"]
        if action in ("", "about:blank"):
            return -1
        if url not in action and domain not in action:
            return 0
        return 1
    return 1


def _submitting_to_email(soup: BeautifulSoup | None) -> int:
    if soup is None:
        return -1
    for form in soup.find_all("form", action=True):
        return -1 if "mailto:" in form["action"] else 1
    return 1


def _abnormal_url(domain: str, url: str) -> int:
    return 1 if re.search(domain, url) else -1


def _redirect(response: requests.Response | None) -> int:
    if response is None:
        return -1
    history_len = len(response.history)
    if history_len <= 1:
        return -1
    if history_len <= 4:
        return 0
    return 1


def _on_mouseover(response: requests.Response | None) -> int:
    if response is None:
        return -1
    return -1 if re.search(r"<script>.+onmouseover.+</script>", response.text) else 1


def _right_click(response: requests.Response | None) -> int:
    if response is None:
        return -1
    return -1 if re.search(r"event\.button\s*==\s*2", response.text) else 1


def _popup_window(response: requests.Response | None) -> int:
    if response is None:
        return -1
    return -1 if re.search(r"prompt\(", response.text) else 1


def _iframe(response: requests.Response | None) -> int:
    if response is None:
        return -1
    return 1 if re.search(r"<iframe|<frameBorder", response.text, re.IGNORECASE) else -1


def _age_of_domain(whois_data: Any) -> int:
    if whois_data is None:
        return -1
    try:
        creation = str(whois_data.creation_date)
        today = time.strftime("%Y-%m-%d")
        reg_year = int(creation.split()[0].split("-")[0])
        today_year = int(today.split("-")[0])
        return 1 if (today_year - reg_year) > 1 else -1
    except Exception:
        return -1


def _dns_record(domain: str) -> int:
    try:
        whois.whois(domain)
        return 1
    except Exception:
        return -1


def _web_traffic(rank: int) -> int:
    return 1 if 0 < rank < 100_000 else -1


def _page_rank(rank: int) -> int:
    return 1 if 0 < rank < 10_000 else -1


def _google_index(url: str) -> int:
    """Check if the URL appears in Google search results."""
    try:
        from googlesearch import search  # optional dependency
        results = list(search(url, num_results=5))
        return 1 if results else -1
    except Exception:
        return -1


def _links_pointing_to_page(response: requests.Response | None) -> int:
    if response is None:
        return -1
    count = len(re.findall(r"<a\s+href=", response.text, re.IGNORECASE))
    if count <= 45:
        return 1
    if count <= 60:
        return 0
    return -1


def _statistical_report(url: str, domain: str) -> int:
    if _SUSPICIOUS_DOMAINS.search(url):
        return -1
    try:
        ip = socket.gethostbyname(domain)
        return -1 if _SUSPICIOUS_IPS.search(ip) else 1
    except Exception:
        return -1


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_features(url: str) -> tuple[list[int], int]:
    """
    Extract all 30 features from *url*.

    Returns:
        (feature_vector, global_rank)
        feature_vector is ordered to match FEATURE_COLUMNS.
    """
    # One-time network calls shared across features
    response, soup = _fetch(url)
    domain = _extract_domain(url)
    whois_data = _whois_safe(domain)
    rank = _global_rank(domain)

    vector: list[int] = [
        _having_ip_address(url),
        _url_length(url),
        _shortening_service(url),
        _having_at_symbol(url),
        _double_slash_redirecting(url),
        _prefix_suffix(url),
        _having_sub_domain(url),
        _ssl_final_state(url),
        _domain_reg_length(whois_data),
        _favicon(soup, url, domain),
        _port(domain),
        _https_token(url),
        _request_url(url, soup, domain),
        _url_of_anchor(url, soup, domain),
        _links_in_tags(url, soup, domain),
        _sfh(url, soup, domain),
        _submitting_to_email(soup),
        _abnormal_url(domain, url),
        _redirect(response),
        _on_mouseover(response),
        _right_click(response),
        _popup_window(response),
        _iframe(response),
        _age_of_domain(whois_data),
        _dns_record(domain),
        _web_traffic(rank),
        _page_rank(rank),
        _google_index(url),
        _links_pointing_to_page(response),
        _statistical_report(url, domain),
    ]

    return vector, rank
