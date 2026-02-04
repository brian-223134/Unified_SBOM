import unittest
import json
import tempfile
import os
from pathlib import Path
from datetime import datetime, timezone
from app.services.export import SBOMExporter
from app.models.unified_sbom import (
    UnifiedSbom, UnifiedComponent, UnifiedAuthor, 
    UnifiedMetadata, UnifiedMetadataComponent
)

'''
실행 방법
python -m app.test.export_test
'''

class TestSBOMExporter(unittest.TestCase):
    def setUp(self):
        """테스트에 사용할 가상 UnifiedSbom 데이터를 준비합니다."""
        # 가상 메타데이터 컴포넌트
        metadata_component = UnifiedMetadataComponent(
            name="test-app",
            type="application", 
            bom_ref="pkg:maven/com.test/test-app@1.0.0",
            version="1.0.0",
            group="com.test",
            purl="pkg:maven/com.test/test-app@1.0.0"
        )
        
        # 가상 메타데이터
        self.metadata = UnifiedMetadata(
            timestamp="2024-01-01T00:00:00Z",
            authors=[
                UnifiedAuthor(name="Test Author", email="test@example.com"),
                UnifiedAuthor(name="Another Author", email=None)
            ],
            tools={
                "components": [
                    {"name": "Quick-BOM-Integrator", "version": "1.0.0"}
                ]
            },
            component=metadata_component
        )
        
        # 가상 컴포넌트들
        self.components = [
            UnifiedComponent(
                name="numpy",
                version="1.24.0", 
                type="library",
                bom_ref="pkg:pypi/numpy@1.24.0",
                purl="pkg:pypi/numpy@1.24.0",
                hashes=[{"alg": "MD5", "content": "abc123hash"}],
                licenses=[{"license": {"id": "BSD-3-Clause", "name": "BSD 3-Clause"}}],
                properties=[
                    {"name": "source_tool", "value": "Syft"},
                    {"name": "source_tool", "value": "Hatbom"}
                ],
                authors=[UnifiedAuthor(name="NumPy Team", email="numpy@python.org")]
            ),
            UnifiedComponent(
                name="requests",
                version="2.31.0",
                type="library", 
                bom_ref="pkg:pypi/requests@2.31.0",
                purl="pkg:pypi/requests@2.31.0",
                licenses=[{"license": {"id": "Apache-2.0", "name": "Apache License 2.0"}}],
                properties=[
                    {"name": "source_tool", "value": "Syft"}
                ],
                authors=[UnifiedAuthor(name="Kenneth Reitz", email="me@kennethreitz.org")]
            )
        ]
        
        # 가상 UnifiedSbom 생성
        self.unified_sbom = UnifiedSbom(
            bom_format="CycloneDX",
            spec_version="1.6", 
            serial_number="urn:uuid:test-unified",
            version=1,
            metadata=self.metadata,
            components=self.components,
            dependencies=[
                {"ref": "pkg:pypi/numpy@1.24.0", "dependsOn": []},
                {"ref": "pkg:pypi/requests@2.31.0", "dependsOn": ["pkg:pypi/urllib3@2.0.0"]}
            ]
        )
        
        self.exporter = SBOMExporter(self.unified_sbom)

    def test_to_dict_basic_structure(self):
        """to_dict()가 기본 CycloneDX 구조를 올바르게 생성하는지 테스트합니다."""
        result = self.exporter.to_dict()
        
        # 필수 필드 검증
        self.assertEqual(result["bomFormat"], "CycloneDX")
        self.assertEqual(result["specVersion"], "1.6")
        self.assertEqual(result["serialNumber"], "urn:uuid:test-unified")
        self.assertEqual(result["version"], 1)
        self.assertIn("metadata", result)
        self.assertIn("components", result)
        self.assertIn("dependencies", result)

    def test_to_dict_metadata_conversion(self):
        """메타데이터가 올바르게 변환되는지 테스트합니다."""
        result = self.exporter.to_dict()
        metadata = result["metadata"]
        
        # 타임스탬프 검증
        self.assertEqual(metadata["timestamp"], "2024-01-01T00:00:00Z")
        
        # Authors 검증
        self.assertEqual(len(metadata["authors"]), 2)
        self.assertEqual(metadata["authors"][0]["name"], "Test Author")
        self.assertEqual(metadata["authors"][0]["email"], "test@example.com")
        self.assertEqual(metadata["authors"][1]["name"], "Another Author")
        self.assertNotIn("email", metadata["authors"][1])  # None인 경우 제외
        
        # Tools 검증  
        self.assertIn("tools", metadata)
        self.assertEqual(metadata["tools"]["components"][0]["name"], "Quick-BOM-Integrator")
        
        # Component 검증
        comp = metadata["component"]
        self.assertEqual(comp["name"], "test-app")
        self.assertEqual(comp["bom-ref"], "pkg:maven/com.test/test-app@1.0.0")

    def test_to_dict_components_conversion(self):
        """컴포넌트들이 올바르게 변환되는지 테스트합니다."""
        result = self.exporter.to_dict()
        components = result["components"]
        
        self.assertEqual(len(components), 2)
        
        # 첫 번째 컴포넌트 (numpy) 검증
        numpy_comp = components[0]
        self.assertEqual(numpy_comp["name"], "numpy")
        self.assertEqual(numpy_comp["version"], "1.24.0")
        self.assertEqual(numpy_comp["bom-ref"], "pkg:pypi/numpy@1.24.0")
        self.assertIn("hashes", numpy_comp)
        self.assertIn("licenses", numpy_comp)
        self.assertIn("properties", numpy_comp) 
        self.assertIn("authors", numpy_comp)
        
        # Authors 변환 확인
        self.assertEqual(len(numpy_comp["authors"]), 1)
        self.assertEqual(numpy_comp["authors"][0]["name"], "NumPy Team")

    def test_to_json_valid_format(self):
        """to_json()이 유효한 JSON 문자열을 생성하는지 테스트합니다."""
        json_str = self.exporter.to_json()
        
        # JSON 파싱이 가능한지 확인
        try:
            parsed = json.loads(json_str)
            self.assertIsInstance(parsed, dict)
        except json.JSONDecodeError:
            self.fail("to_json()이 유효하지 않은 JSON을 생성했습니다")
            
        # 들여쓰기 테스트
        json_str_indent4 = self.exporter.to_json(indent=4)
        self.assertNotEqual(json_str, json_str_indent4)  # 들여쓰기가 다르면 내용이 달라야 함

    def test_get_filename_with_component(self):
        """컴포넌트 이름이 있을 때 올바른 파일명을 생성하는지 테스트합니다."""
        filename = self.exporter.get_filename()
        self.assertEqual(filename, "test-app_unified_sbom.json")

    def test_get_filename_special_characters(self):
        """파일명에 특수문자가 있을 때 안전하게 변환되는지 테스트합니다."""
        # 특수문자가 포함된 컴포넌트 이름으로 테스트
        self.metadata.component.name = "test/app:v1.0"
        filename = self.exporter.get_filename()
        self.assertEqual(filename, "test_app_v1.0_unified_sbom.json")

    def test_get_filename_no_component(self):
        """컴포넌트가 없을 때 기본 파일명을 사용하는지 테스트합니다."""
        self.unified_sbom.metadata.component = None
        filename = self.exporter.get_filename()
        self.assertEqual(filename, "unified_sbom.json")

    def test_save_to_file(self):
        """파일 저장 기능이 올바르게 동작하는지 테스트합니다."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = os.path.join(temp_dir, "test_output.json")
            
            # 파일 저장 
            saved_path = self.exporter.save_to_file(output_path)
            
            # 파일이 생성되었는지 확인
            self.assertTrue(os.path.exists(saved_path))
            
            # 파일 내용이 올바른지 확인
            with open(saved_path, 'r', encoding='utf-8') as f:
                loaded_data = json.load(f)
                
            expected_data = self.exporter.to_dict()
            self.assertEqual(loaded_data, expected_data)

    def test_save_to_file_creates_directory(self):
        """존재하지 않는 디렉토리에 저장할 때 디렉토리를 생성하는지 테스트합니다."""
        with tempfile.TemporaryDirectory() as temp_dir:
            nested_path = os.path.join(temp_dir, "nested", "deep", "test.json")
            
            saved_path = self.exporter.save_to_file(nested_path)
            
            # 파일과 디렉토리가 모두 생성되었는지 확인
            self.assertTrue(os.path.exists(saved_path))
            self.assertTrue(os.path.isfile(saved_path))

    def test_get_summary(self):
        """get_summary()가 올바른 요약 정보를 생성하는지 테스트합니다."""
        summary = self.exporter.get_summary()
        
        # 기본 정보 검증
        self.assertEqual(summary["bom_format"], "CycloneDX")
        self.assertEqual(summary["spec_version"], "1.6")
        self.assertEqual(summary["total_components"], 2)
        self.assertEqual(summary["total_dependencies"], 2)
        self.assertEqual(summary["metadata_component"], "test-app")
        
        # 소스별 컴포넌트 수 검증 
        self.assertEqual(summary["components_from_syft"], 2)  # numpy와 requests 모두 Syft 포함
        self.assertEqual(summary["components_from_hatbom"], 1)  # numpy만 Hatbom 포함

    def test_empty_metadata_handling(self):
        """메타데이터가 None일 때도 올바르게 처리하는지 테스트합니다."""
        self.unified_sbom.metadata = None
        exporter = SBOMExporter(self.unified_sbom)
        
        result = exporter.to_dict()
        self.assertEqual(result["metadata"], {})
        
        summary = exporter.get_summary()
        self.assertIsNone(summary["timestamp"])
        self.assertIsNone(summary["metadata_component"])

if __name__ == "__main__":
    unittest.main()
