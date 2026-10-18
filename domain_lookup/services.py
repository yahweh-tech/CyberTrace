from datetime import datetime

import requests

from .models import DomainLookup


class DomainLookupService:

    @staticmethod
    def _parse_rdap_date(value):
        if not value:
            return None
        try:
            return datetime.strptime(value[:10], "%Y-%m-%d").date()
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _extract_entity_name(entities, roles):
        for entity in entities or []:
            if not set(roles).intersection(entity.get("roles", [])):
                continue
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1:
                for field in vcard[1]:
                    if field[0] == "fn":
                        return field[3]
            if entity.get("handle"):
                return entity["handle"]
        return ""

    @staticmethod
    def lookup(domain):
        """
        Resolve domain registration data via RDAP (Registration Data Access Protocol).
        Falls back to mock data when RDAP is unavailable.
        """
        domain = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]

        try:
            response = requests.get(
                f"https://rdap.org/domain/{domain}",
                timeout=10,
                headers={"Accept": "application/rdap+json"},
            )
            response.raise_for_status()
            data = response.json()

            events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
            name_servers = ", ".join(
                ns.get("ldhName", "") for ns in data.get("nameservers", [])
            )

            return {
                "domain": domain,
                "registrar": DomainLookupService._extract_entity_name(
                    data.get("entities", []), ["registrar"]
                ),
                "registrant_org": DomainLookupService._extract_entity_name(
                    data.get("entities", []), ["registrant"]
                ),
                "creation_date": DomainLookupService._parse_rdap_date(
                    events.get("registration")
                ),
                "expiry_date": DomainLookupService._parse_rdap_date(
                    events.get("expiration")
                ),
                "name_servers": name_servers,
                "hosting_provider": name_servers.split(",")[0].strip() if name_servers else "",
            }
        except (requests.RequestException, ValueError, KeyError):
            pass

        return {
            "domain": domain,
            "registrar": "Unknown Registrar",
            "registrant_org": "",
            "creation_date": None,
            "expiry_date": None,
            "name_servers": "",
            "hosting_provider": "",
        }

    @staticmethod
    def save_lookup(investigation, domain, user=None):
        data = DomainLookupService.lookup(domain)

        lookup = DomainLookup.objects.create(
            investigation=investigation,
            domain=data["domain"],
            registrar=data["registrar"],
            registrant_org=data["registrant_org"],
            creation_date=data["creation_date"],
            expiry_date=data["expiry_date"],
            name_servers=data["name_servers"],
            hosting_provider=data["hosting_provider"],
        )

        if user:
            from timeline.services import TimelineService

            TimelineService.log(
                investigation,
                user,
                "Domain Lookup Completed",
                f"WHOIS lookup for {data['domain']} — registrar: {data['registrar']}.",
            )

        return lookup
