import os
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from investigations.models import Investigation
from .models import BinaryAnalysis
from .services import ReverseEngineeringService

User = get_user_model()


class ReverseEngineeringServiceTests(TestCase):

    def test_entropy_calculation(self):
        # All zeros -> 0 entropy
        zero_data = b"\x00" * 1000
        self.assertEqual(ReverseEngineeringService.calculate_entropy(zero_data), 0.0)

        # Uniform distribution of all 256 byte values -> maximum entropy (~8.0)
        uniform_data = bytes(range(256)) * 10
        entropy = ReverseEngineeringService.calculate_entropy(uniform_data)
        self.assertAlmostEqual(entropy, 8.0, places=1)

    def test_string_and_ioc_extraction(self):
        sample_payload = (
            b"Hello World! This is a test binary. "
            b"Contact C2 server at https://malicious-c2-domain.com/beacon "
            b"or direct connect to 185.190.140.22 on port 443. "
            b"Registry run key: HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        )
        strings = ReverseEngineeringService.extract_strings(sample_payload)
        self.assertTrue(any("malicious-c2-domain.com" in s for s in strings))
        self.assertTrue(any("185.190.140.22" in s for s in strings))

        iocs = ReverseEngineeringService.extract_iocs(strings)
        self.assertIn("185.190.140.22", iocs["ips"])
        self.assertTrue(any("malicious-c2-domain.com" in url for url in iocs["urls"]))

    def test_analyze_real_pe_binary_if_available(self):
        # Test on notepad.exe or python.exe
        target_path = r"C:\Windows\System32\notepad.exe"
        if not os.path.exists(target_path):
            target_path = r"C:\Windows\System32\cmd.exe"

        if os.path.exists(target_path):
            with open(target_path, "rb") as f:
                raw_bytes = f.read()

            result = ReverseEngineeringService.analyze_bytes(raw_bytes, "notepad_sample.exe")
            self.assertIn("Windows PE", result["file_type"])
            self.assertTrue(result["sha256"])
            self.assertTrue(result["md5"])
            self.assertGreater(len(result["sections_data"]), 0)
            self.assertGreater(result["entropy"], 0.0)
            self.assertIn("0x", result["entry_point"])


class ReverseEngineeringViewTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username="analyst_test",
            password="TestPassword123!",
        )
        self.investigation = Investigation.objects.create(
            title="Operation Phantom Voice",
            description="Investigating suspicious caller VoIP payload",
            investigator=self.user,
        )

    def test_upload_page_renders_for_authenticated_user(self):
        self.client.force_login(self.user)
        url = reverse("reverse_engineering:upload", args=[self.investigation.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Reverse Engineering & Binary Triage")

    def test_upload_and_results_flow(self):
        self.client.force_login(self.user)
        test_content = b"MZ\x90\x00\x03\x00\x00\x00Dummy binary content with URL http://evil-payload-site.com and IP 45.33.32.156"
        uploaded_file = SimpleUploadedFile("suspicious_beacon.exe", test_content)

        upload_url = reverse("reverse_engineering:upload", args=[self.investigation.id])
        response = self.client.post(
            upload_url,
            {
                "source_label": "beacon_stage1.exe",
                "sample_file": uploaded_file,
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)

        # Verify DB object
        self.assertEqual(BinaryAnalysis.objects.count(), 1)
        analysis = BinaryAnalysis.objects.first()
        self.assertEqual(analysis.file_name, "beacon_stage1.exe")
        self.assertIn("45.33.32.156", analysis.extracted_iocs["ips"])

        # Check result page contains the extracted IOCs and trace buttons
        self.assertContains(response, "45.33.32.156")
        self.assertContains(response, "Trace IP")
