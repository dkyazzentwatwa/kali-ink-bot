"""
Kali tool profile catalog.

Profiles map Kali metapackages to grouped tool inventories so runtime checks
and commands can scale without hardcoding one-off lists everywhere.
"""

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class KaliToolProfile:
    """Metadata for a Kali metapackage profile."""
    name: str
    package: str
    description: str
    tools: List[str]


BUILTIN_PROFILES: Dict[str, KaliToolProfile] = {
    "web": KaliToolProfile(
        name="web",
        package="kali-tools-web",
        description="Kali web application assessment tools",
        tools=[
            "burpsuite", "nikto", "sqlmap", "wfuzz", "wafw00f", "whatweb",
            "wpscan", "dirb", "dirbuster", "joomscan", "skipfish", "sslyze",
            "sslscan", "httprint", "commix", "wapiti", "mitmproxy", "zap",
            "nmap", "hydra",
        ],
    ),
    "vulnerability": KaliToolProfile(
        name="vulnerability",
        package="kali-tools-vulnerability",
        description="Kali vulnerability analysis tools",
        tools=[
            "nikto", "nmap", "slowhttptest", "thc-ssl-dos", "siege", "gvm",
            "enumiax", "bed", "lynis", "unix-privesc-check", "sctpscan",
            "sfuzz", "sipvicious", "sipp", "sipsak", "spike", "peass",
            "voiphopper", "cisco-torch",
        ],
    ),
    "passwords": KaliToolProfile(
        name="passwords",
        package="kali-tools-passwords",
        description="Kali password auditing and cracking tools",
        tools=[
            "hydra", "john", "hashcat", "ncrack", "medusa", "cewl", "crunch",
            "seclists", "wordlists", "ophcrack", "pdfcrack", "rainbowcrack",
            "smbmap", "samdump2", "pack", "patator", "rsmangler",
            "thc-pptp-bruter", "truecrack", "sqldict",
        ],
    ),
    "information-gathering": KaliToolProfile(
        name="information-gathering",
        package="kali-tools-information-gathering",
        description="Kali information gathering and enumeration tools",
        tools=[
            "nmap", "masscan", "dnsenum", "dnsrecon", "dnswalk", "enum4linux",
            "firewalk", "fping", "hping3", "ike-scan", "nbtscan", "onesixtyone",
            "p0f", "recon-ng", "smtp-user-enum", "snmpcheck", "sslh", "sslscan",
            "sslyze", "theharvester", "unicornscan", "wafw00f",
        ],
    ),
}


def get_profile(name: str) -> KaliToolProfile | None:
    """Get a profile by its canonical name."""
    return BUILTIN_PROFILES.get(name)


def list_profiles() -> List[KaliToolProfile]:
    """Return all builtin profiles in stable key order."""
    return [BUILTIN_PROFILES[key] for key in sorted(BUILTIN_PROFILES)]
