import unittest
import os
import json
from app.services.parse import SBOMParser
from app.models.hatbom_sbom import HatbomSbom
from app.models.syft_sbom import SyftSbom

'''
실행 방법
python -m app.test.parse_test
'''

class TestSBOMParser(unittest.TestCase):
    def setUp(self):
        """테스트에 사용할 파서와 가상 데이터를 준비합니다."""
        self.parser = SBOMParser()
        
        # 가상 Hatbom JSON 데이터
        self.hatbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": "urn:uuid:test-hatbom",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "authors": [{"name": "Test Author", "email": "test@example.com"}],
                "component": {
                    "group": "com.test",
                    "name": "test-app",
                    "version": "1.0.0",
                    "type": "application",
                    "bom-ref": "pkg:maven/com.test/test-app@1.0.0",
                    "purl": "pkg:maven/com.test/test-app@1.0.0"
                }
            },
            "components": [
                {
                    "name": "numpy",
                    "version": "1.24.0",
                    "type": "library",
                    "bom-ref": "pkg:pypi/numpy@1.24.0",
                    "purl": "pkg:pypi/numpy@1.24.0",
                    "hashes": [
                        {"alg": "MD5", "content": "abc123hash"}
                    ]
                }
            ]
        }
        
        # 가상 Syft JSON 데이터 (실제 _is_syft 메소드 로직에 맞게)
        self.syft_data = {
            "$schema": "https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:test-syft",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {
                    "components": [
                        {
                            "name": "syft",
                            "version": "0.100.0",
                            "type": "application"
                        }
                    ]
                },
                "component": {
                    "bom-ref": "test-app",
                    "type": "file",
                    "name": "test-app"
                }
            },
            "components": [
                {
                    "bom-ref": "pkg:pypi/requests@2.31.0",
                    "type": "library",
                    "name": "requests",
                    "version": "2.31.0",
                    "purl": "pkg:pypi/requests@2.31.0",
                    "licenses": [
                        {
                            "license": {
                                "id": "Apache-2.0",
                                "name": "Apache Software License"
                            }
                        }
                    ],
                    "author": "Kenneth Reitz <me@kennethreitz.org>",
                    "properties": [
                        {
                            "name": "syft:package:foundBy",
                            "value": "python-package-cataloger"
                        }
                    ]
                }
            ]
        }

    def test_detect_syft_format(self):
        """Syft 형식 JSON이 올바르게 감지되는지 테스트합니다."""
        self.assertTrue(self.parser._is_syft(self.syft_data))
        self.assertFalse(self.parser._is_syft(self.hatbom_data))

    def test_parse_hatbom_from_dict(self):
        """Hatbom 데이터가 올바르게 파싱되는지 테스트합니다."""
        hatbom_obj = HatbomSbom.from_json(self.hatbom_data)
        
        self.assertEqual(hatbom_obj.bom_format, "CycloneDX")
        self.assertEqual(hatbom_obj.spec_version, "1.4")
        self.assertEqual(len(hatbom_obj.components), 1)
        self.assertEqual(hatbom_obj.components[0].name, "numpy")
        self.assertEqual(hatbom_obj.components[0].hashes[0].content, "abc123hash")

    def test_parse_syft_from_dict(self):
        """Syft 데이터가 올바르게 파싱되는지 테스트합니다."""
        syft_obj = SyftSbom.from_json(self.syft_data)
        
        self.assertEqual(syft_obj.bom_format, "CycloneDX")
        self.assertEqual(syft_obj.spec_version, "1.6")
        self.assertEqual(len(syft_obj.components), 1)
        self.assertEqual(syft_obj.components[0].name, "requests")
        self.assertEqual(syft_obj.components[0].author, "Kenneth Reitz <me@kennethreitz.org>")

    def test_file_not_found_error(self):
        """존재하지 않는 파일에 대한 에러 처리를 테스트합니다."""
        with self.assertRaises(FileNotFoundError):
            self.parser.parse("nonexistent_file.json")

if __name__ == "__main__":
    unittest.main()