import unittest
import json
from app.services.parse import SBOMParser
from app.models.hatbom_sbom import HatbomSbom
from app.models.syft_sbom import SyftSbom

class TestSBOMParser(unittest.TestCase):
    def setUp(self):
        self.parser = SBOMParser()
        
        # 테스트 데이터 정의 (기존과 동일)
        self.hatbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": "urn:uuid:test-hatbom",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "authors": [{"name": "Test Author", "email": "test@example.com"}],
                "component": {
                    "group": "com.test", "name": "test-app", "version": "1.0.0",
                    "type": "application", "bom-ref": "pkg:maven...", "purl": "pkg:maven..."
                }
            },
            "components": [
                {
                    "name": "numpy", "version": "1.24.0", "type": "library",
                    "bom-ref": "pkg:pypi/numpy@1.24.0", "purl": "pkg:pypi/numpy@1.24.0",
                    "hashes": [{"alg": "MD5", "content": "abc123hash"}]
                }
            ]
        }
        
        self.syft_data = {
            "$schema": "https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:test-syft", "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"name": "syft", "version": "0.100.0", "type": "application"}]},
                "component": {"bom-ref": "test-app", "type": "file", "name": "test-app"}
            },
            "components": [
                {
                    "bom-ref": "pkg:pypi/requests@2.31.0", "type": "library", "name": "requests", "version": "2.31.0",
                    "purl": "pkg:pypi/requests@2.31.0",
                    "licenses": [{"license": {"id": "Apache-2.0", "name": "Apache Software License"}}],
                    "author": "Kenneth Reitz <me@kennethreitz.org>",
                    "properties": [{"name": "syft:package:foundBy", "value": "python-package-cataloger"}]
                }
            ]
        }

    def test_detect_syft_format(self):
        """_is_syft 메소드 로직 검증"""
        self.assertTrue(self.parser._is_syft(self.syft_data))
        self.assertFalse(self.parser._is_syft(self.hatbom_data))

    def test_parse_hatbom_from_dict(self):
        """HatbomSbom.from_json 메서드 검증"""
        # 실제 파일 파싱 대신 from_json 메서드를 직접 테스트하여 파일 의존성 제거
        hatbom_obj = HatbomSbom.from_json(self.hatbom_data)
        
        self.assertEqual(hatbom_obj.bom_format, "CycloneDX")
        self.assertEqual(len(hatbom_obj.components), 1)
        self.assertEqual(hatbom_obj.components[0].name, "numpy")
        self.assertEqual(hatbom_obj.components[0].hashes[0].content, "abc123hash")

    def test_parse_syft_from_dict(self):
        """SyftSbom.from_json 메서드 검증"""
        syft_obj = SyftSbom.from_json(self.syft_data)
        
        self.assertEqual(syft_obj.bom_format, "CycloneDX")
        self.assertEqual(len(syft_obj.components), 1)
        self.assertEqual(syft_obj.components[0].name, "requests")
        # author 파싱 확인
        self.assertIn("Kenneth Reitz", syft_obj.components[0].author)

    def test_file_not_found_error(self):
        """파일이 없을 때 에러 발생 확인"""
        with self.assertRaises(FileNotFoundError):
            self.parser.parse("nonexistent_file.json")

if __name__ == "__main__":
    unittest.main()