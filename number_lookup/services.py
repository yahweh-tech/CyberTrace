import os

import requests

from .models import NumberLookup


class NumberLookupError(Exception):
    """Raised whenever real phone intelligence cannot be retrieved.

    This tool never fabricates carrier/country/line-type data for an
    investigation — if the real lookup fails, the caller must be told
    plainly rather than shown made-up results.
    """


class NumberLookupService:

    @staticmethod
    def lookup(phone_number):
        """
        Phone intelligence via NumVerify (apilayer.net), free tier.
        Raises NumberLookupError on any failure — no mock fallback.
        """
        api_key = os.getenv("NUMVERIFY_API_KEY")

        if not api_key:
            raise NumberLookupError(
                "NUMVERIFY_API_KEY is not configured. Add it to your .env file "
                "(get a free key at https://numverify.com)."
            )

        try:
            response = requests.get(
                # Current APILayer marketplace endpoint: HTTPS + "apikey" header.
                # (The old apilayer.net/api/validate?access_key=... endpoint is
                # legacy and rejects keys issued through the new dashboard.)
                "https://api.apilayer.com/number_verification/validate",
                headers={"apikey": api_key},
                params={"number": phone_number},
                timeout=10,
            )
            data = response.json()
        except requests.RequestException as exc:
            raise NumberLookupError(f"NumVerify API request failed: {exc}") from exc
        except ValueError as exc:
            raise NumberLookupError("NumVerify returned an unreadable response.") from exc

        if response.status_code != 200:
            info = (
                data.get("message") or data.get("error", {}).get("info")
                if isinstance(data, dict) else None
            )
            raise NumberLookupError(
                info or f"NumVerify API returned HTTP {response.status_code}."
            )

        if isinstance(data, dict) and "error" in data:
            info = data["error"].get("info", "NumVerify API returned an error.")
            raise NumberLookupError(info)

        if not data.get("valid"):
            raise NumberLookupError(
                f"'{phone_number}' could not be validated as a real, reachable "
                "phone number by NumVerify."
            )

        line_type = (data.get("line_type") or "").strip()

        return {
            "country": data.get("country_name") or "Unknown",
            "carrier": data.get("carrier") or "Unknown",
            "line_type": line_type.title() if line_type else "Unknown",
            "is_virtual": line_type.lower() in ("voip", "virtual"),
            "provider": data.get("carrier") or "Unknown",
        }

    @staticmethod
    def save_lookup(investigation, phone_number, user=None):
        # Raises NumberLookupError if the real lookup fails; the caller
        # (the view) is responsible for surfacing that to the user.
        data = NumberLookupService.lookup(phone_number)

        lookup = NumberLookup.objects.create(
            investigation=investigation,
            phone_number=phone_number,
            country=data["country"],
            carrier=data["carrier"],
            line_type=data["line_type"],
            is_virtual=data["is_virtual"],
            provider=data["provider"],
        )

        if user:
            from timeline.services import TimelineService

            TimelineService.log(
                investigation,
                user,
                "Phone Lookup Completed",
                f"Number {phone_number} traced to {data['country']} ({data['carrier']}).",
            )

        return lookup
