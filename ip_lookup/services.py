import requests

from django.conf import settings

from .models import IPLookup


class IPLookupService:

    @staticmethod
    def lookup(ip_address):
        """
        Resolve IP geolocation via ip-api.com (free tier).
        Falls back to mock data when the API is unavailable.
        """
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip_address}",
                params={"fields": "status,message,country,regionName,city,isp,org,proxy,lat,lon"},
                timeout=10,
            )
            response.raise_for_status()
            data = response.json()

            if data.get("status") == "success":
                return {
                    "country": data.get("country", ""),
                    "region": data.get("regionName", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "is_proxy": data.get("proxy", False),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                }
        except (requests.RequestException, ValueError):
            pass

        return {
            "country": "Unknown",
            "region": "",
            "city": "",
            "isp": "Unknown ISP",
            "org": "",
            "is_proxy": False,
            "latitude": None,
            "longitude": None,
        }

    @staticmethod
    def save_lookup(investigation, ip_address, user=None):
        data = IPLookupService.lookup(ip_address)

        lookup = IPLookup.objects.create(
            investigation=investigation,
            ip_address=ip_address,
            country=data["country"],
            region=data["region"],
            city=data["city"],
            isp=data["isp"],
            org=data["org"],
            is_proxy=data["is_proxy"],
            latitude=data["latitude"],
            longitude=data["longitude"],
        )

        if user:
            from timeline.services import TimelineService

            TimelineService.log(
                investigation,
                user,
                "IP Lookup Completed",
                f"Traced IP {ip_address} to {data['city']}, {data['country']}.",
            )

        return lookup
