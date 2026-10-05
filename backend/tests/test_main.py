import os
import sys
import unittest
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

os.environ["TESTING"] = "1"

from fastapi.testclient import TestClient
from main import app
from app.core.database import init_db

class TestMainApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        self.client = TestClient(app)

    def test_health_check(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

    def test_summary_api(self):
        response = self.client.get("/api/v1/summary?tenant_id=tenant-01")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["tenant_id"], "tenant-01")
        self.assertIn("total_events", data)

if __name__ == "__main__":
    unittest.main()
