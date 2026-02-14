"""
Project Inkling - Reconnaissance Module

Lightweight reconnaissance utilities for DNS enumeration, WHOIS lookups,
and subdomain discovery. Optimized for Raspberry Pi Zero 2W.
"""

import asyncio
import logging
import socket
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Common subdomains for enumeration
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "api", "dev", "staging",
    "test", "admin", "portal", "vpn", "remote", "secure", "shop", "store",
    "blog", "forum", "wiki", "support", "help", "docs", "cdn", "static",
    "assets", "img", "images", "media", "upload", "files", "download",
    "git", "gitlab", "github", "jenkins", "ci", "build", "deploy", "app",
    "apps", "m", "mobile", "beta", "alpha", "demo", "status", "health",
    "monitor", "logs", "login", "auth", "sso", "oauth", "id", "account",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "search", "proxy", "gateway", "lb", "loadbalancer", "cache", "backup",
]


@dataclass
class DNSRecord:
    """DNS record data."""
    record_type: str
    value: str
    ttl: Optional[int] = None


@dataclass
class WHOISResult:
    """WHOIS lookup result."""
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    registrant_country: Optional[str] = None
    emails: List[str] = field(default_factory=list)
    raw: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "registrar": self.registrar,
            "creation_date": self.creation_date,
            "expiration_date": self.expiration_date,
            "updated_date": self.updated_date,
            "name_servers": self.name_servers,
            "status": self.status,
            "registrant_country": self.registrant_country,
            "emails": self.emails,
        }


@dataclass
class ReconResult:
    """Combined reconnaissance result."""
    target: str
    dns_records: Dict[str, List[DNSRecord]] = field(default_factory=dict)
    whois: Optional[WHOISResult] = None
    subdomains: List[str] = field(default_factory=list)
    reverse_dns: Optional[str] = None
    zone_transfer_possible: bool = False
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "dns_records": {
                rtype: [{"type": r.record_type, "value": r.value, "ttl": r.ttl} for r in records]
                for rtype, records in self.dns_records.items()
            },
            "whois": self.whois.to_dict() if self.whois else None,
            "subdomains": self.subdomains,
            "reverse_dns": self.reverse_dns,
            "zone_transfer_possible": self.zone_transfer_possible,
            "errors": self.errors,
        }


class ReconEngine:
    """
    Reconnaissance engine for target enumeration.

    Uses lightweight libraries suitable for Pi Zero 2W:
    - dnspython for DNS queries
    - python-whois for WHOIS lookups
    """

    def __init__(
        self,
        dns_timeout: float = 5.0,
        whois_timeout: float = 10.0,
        max_subdomains: int = 50,
    ):
        """Initialize recon engine."""
        self.dns_timeout = dns_timeout
        self.whois_timeout = whois_timeout
        self.max_subdomains = max_subdomains
        self._resolver = None

    def _get_resolver(self):
        """Get or create DNS resolver."""
        if self._resolver is None:
            try:
                import dns.resolver
                self._resolver = dns.resolver.Resolver()
                self._resolver.timeout = self.dns_timeout
                self._resolver.lifetime = self.dns_timeout
            except ImportError:
                logger.warning("dnspython not installed")
                return None
        return self._resolver

    async def full_recon(self, target: str) -> ReconResult:
        """
        Perform full reconnaissance on a target.

        Includes DNS enumeration, WHOIS lookup, and subdomain discovery.
        """
        result = ReconResult(target=target)

        # Determine if target is IP or domain
        is_ip = self._is_ip(target)

        if is_ip:
            # For IPs, do reverse DNS
            try:
                result.reverse_dns = await self.reverse_dns(target)
            except Exception as e:
                result.errors.append(f"Reverse DNS failed: {str(e)}")
        else:
            # For domains, do full enumeration
            try:
                dns_result = await self.dns_enum(target)
                result.dns_records = dns_result
            except Exception as e:
                result.errors.append(f"DNS enumeration failed: {str(e)}")

            try:
                result.whois = await self.whois_lookup(target)
            except Exception as e:
                result.errors.append(f"WHOIS lookup failed: {str(e)}")

            try:
                result.subdomains = await self.subdomain_enum(target)
            except Exception as e:
                result.errors.append(f"Subdomain enumeration failed: {str(e)}")

            # Check for zone transfer
            try:
                result.zone_transfer_possible = await self._check_zone_transfer(target)
            except Exception:
                pass

        return result

    async def dns_enum(self, domain: str) -> Dict[str, List[DNSRecord]]:
        """
        Enumerate DNS records for a domain.

        Returns A, AAAA, MX, NS, TXT, SOA, CNAME records.
        """
        resolver = self._get_resolver()
        if not resolver:
            return {}

        import dns.resolver
        import dns.exception

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
        results: Dict[str, List[DNSRecord]] = {}

        for rtype in record_types:
            try:
                # Run DNS query in thread to avoid blocking
                answers = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda rt=rtype: resolver.resolve(domain, rt)
                )

                records = []
                for rdata in answers:
                    value = str(rdata)
                    # Handle MX records specially (include priority)
                    if rtype == "MX":
                        value = f"{rdata.preference} {rdata.exchange}"

                    records.append(DNSRecord(
                        record_type=rtype,
                        value=value,
                        ttl=answers.ttl if hasattr(answers, 'ttl') else None,
                    ))

                if records:
                    results[rtype] = records

            except dns.resolver.NXDOMAIN:
                logger.debug(f"No {rtype} records for {domain}")
            except dns.resolver.NoAnswer:
                logger.debug(f"No answer for {rtype} on {domain}")
            except dns.exception.Timeout:
                logger.debug(f"Timeout querying {rtype} for {domain}")
            except Exception as e:
                logger.debug(f"Error querying {rtype} for {domain}: {e}")

        return results

    async def whois_lookup(self, target: str) -> Optional[WHOISResult]:
        """
        Perform WHOIS lookup on domain or IP.

        Uses python-whois library.
        """
        try:
            import whois
        except ImportError:
            logger.warning("python-whois not installed")
            return None

        try:
            # Run WHOIS in thread (it's blocking I/O)
            w = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: whois.whois(target)
            )

            if not w:
                return None

            # Extract dates (handle various formats)
            def format_date(d):
                if d is None:
                    return None
                if isinstance(d, list):
                    d = d[0] if d else None
                return str(d) if d else None

            # Extract emails
            emails = []
            if w.emails:
                if isinstance(w.emails, list):
                    emails = w.emails
                else:
                    emails = [w.emails]

            # Extract name servers
            name_servers = []
            if w.name_servers:
                if isinstance(w.name_servers, list):
                    name_servers = [str(ns).lower() for ns in w.name_servers]
                else:
                    name_servers = [str(w.name_servers).lower()]

            # Extract status
            status = []
            if w.status:
                if isinstance(w.status, list):
                    status = w.status
                else:
                    status = [w.status]

            return WHOISResult(
                domain=target,
                registrar=str(w.registrar) if w.registrar else None,
                creation_date=format_date(w.creation_date),
                expiration_date=format_date(w.expiration_date),
                updated_date=format_date(w.updated_date),
                name_servers=name_servers,
                status=status,
                registrant_country=str(w.country) if hasattr(w, 'country') and w.country else None,
                emails=emails,
                raw=str(w.text) if hasattr(w, 'text') else "",
            )

        except Exception as e:
            logger.error(f"WHOIS lookup failed for {target}: {e}")
            return None

    async def reverse_dns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup for an IP address."""
        try:
            # Use socket.gethostbyaddr in thread
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: socket.gethostbyaddr(ip)
            )
            return result[0] if result else None
        except socket.herror:
            return None
        except Exception as e:
            logger.debug(f"Reverse DNS failed for {ip}: {e}")
            return None

    async def subdomain_enum(
        self,
        domain: str,
        wordlist: Optional[List[str]] = None,
    ) -> List[str]:
        """
        Enumerate subdomains using DNS resolution.

        Uses a common subdomain wordlist by default.
        """
        resolver = self._get_resolver()
        if not resolver:
            return []

        import dns.resolver
        import dns.exception

        subdomains_to_check = wordlist or COMMON_SUBDOMAINS
        found_subdomains = []

        # Limit concurrent checks to avoid overwhelming Pi
        semaphore = asyncio.Semaphore(5)

        async def check_subdomain(subdomain: str) -> Optional[str]:
            async with semaphore:
                fqdn = f"{subdomain}.{domain}"
                try:
                    # Quick A record check
                    await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: resolver.resolve(fqdn, "A")
                    )
                    return fqdn
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                    return None
                except Exception:
                    return None

        # Check subdomains concurrently (limited)
        tasks = [check_subdomain(sub) for sub in subdomains_to_check[:self.max_subdomains]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, str):
                found_subdomains.append(result)

        return sorted(found_subdomains)

    async def _check_zone_transfer(self, domain: str) -> bool:
        """
        Check if DNS zone transfer is possible (AXFR).

        This is a security vulnerability if enabled.
        """
        resolver = self._get_resolver()
        if not resolver:
            return False

        try:
            import dns.zone
            import dns.query
            import dns.resolver

            # Get NS records
            ns_records = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: resolver.resolve(domain, "NS")
            )

            for ns in ns_records:
                ns_host = str(ns).rstrip(".")
                try:
                    # Attempt zone transfer
                    zone = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=3))
                    )
                    if zone:
                        return True
                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"Zone transfer check failed: {e}")

        return False

    async def quick_port_scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        timeout: float = 1.0,
    ) -> List[Tuple[int, bool]]:
        """
        Quick TCP connect scan for common ports.

        Uses asyncio for concurrent checks without nmap.
        """
        if ports is None:
            # Common ports for quick scan
            ports = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443,
            ]

        results = []
        semaphore = asyncio.Semaphore(10)  # Limit concurrent connections

        async def check_port(port: int) -> Tuple[int, bool]:
            async with semaphore:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port),
                        timeout=timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    return (port, True)
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return (port, False)

        tasks = [check_port(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter to only open ports and handle exceptions
        open_ports = []
        for result in results:
            if isinstance(result, tuple) and result[1]:
                open_ports.append(result)

        return sorted(open_ports)

    @staticmethod
    def _is_ip(target: str) -> bool:
        """Check if target is an IP address."""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            pass

        try:
            socket.inet_pton(socket.AF_INET6, target)
            return True
        except socket.error:
            pass

        return False

    @staticmethod
    def format_dns_summary(records: Dict[str, List[DNSRecord]]) -> str:
        """Format DNS records for display."""
        lines = []
        for rtype, recs in sorted(records.items()):
            for rec in recs:
                lines.append(f"  {rtype:6} {rec.value}")
        return "\n".join(lines) if lines else "  No DNS records found"

    @staticmethod
    def format_whois_summary(whois: WHOISResult) -> str:
        """Format WHOIS result for display."""
        lines = []
        if whois.registrar:
            lines.append(f"  Registrar: {whois.registrar}")
        if whois.creation_date:
            lines.append(f"  Created: {whois.creation_date}")
        if whois.expiration_date:
            lines.append(f"  Expires: {whois.expiration_date}")
        if whois.name_servers:
            lines.append(f"  NS: {', '.join(whois.name_servers[:3])}")
        if whois.registrant_country:
            lines.append(f"  Country: {whois.registrant_country}")
        return "\n".join(lines) if lines else "  No WHOIS data"
