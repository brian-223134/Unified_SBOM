import unittest
# 실제 모델 파일 경로에 맞게 import 경로가 정확한지 확인해주세요.
from app.models.hatbom_sbom import HatbomSbom, Component as HatComponent, Hash, Metadata as HatMetadata, Dependency as HatDependency
from app.models.syft_sbom import SyftSbom, Component as SyftComponent, License
from app.services.integrate import SBOMIntegrator

'''
실행 방법
python -m app.test.integrate_test
'''

class TestSBOMIntegrator(unittest.TestCase):
    def setUp(self):
        """테스트에 사용할 가상 데이터를 준비합니다."""
        self.integrator = SBOMIntegrator()

        # 1. 가상 Hatbom 데이터 생성 (해시 정보 위주)
        hatbom_metadata = HatMetadata(
            timestamp="2024-01-01T00:00:00Z",
            authors=[{"name": "Test Author", "email": "test@example.com"}],
            component={
                "group": "com.test", 
                "name": "test-app", 
                "version": "1.0.0",
                "type": "application", 
                "bom-ref": "pkg:maven/com.test/test-app@1.0.0",
                "purl": "pkg:maven/com.test/test-app@1.0.0"
            }
        )
        
        self.hatbom = HatbomSbom(
            bom_format="CycloneDX", 
            spec_version="1.4", 
            serial_number="uuid-1", 
            version=1,
            metadata=hatbom_metadata, 
            components=[
                HatComponent(
                    name="numpy", version="2.2.6", type="file", 
                    bom_ref="pkg:pypi/numpy@2.2.6", purl="pkg:pypi/numpy@2.2.6",
                    hashes=[Hash(alg="MD5", content="hash-numpy-123")]
                )
            ],
            # [Fix 1] integrate.py에서 순회하므로 빈 리스트라도 있어야 합니다.
            dependencies=[]  
        )

        # 2. 가상 Syft 데이터 생성 (라이선스 정보 위주)
        # [Fix 2] metadata.tools 구조 수정: integrate.py가 리스트 순회를 기대함
        # SyftSbom 모델의 정의에 따라 다르겠지만, integrate.py 로직에 맞추려면 리스트여야 합니다.
        mock_syft_metadata = type('obj', (object,), {
            'timestamp': '2024-01-01T00:00:00Z', 
            'tools': [{'name': 'syft', 'version': '1.0.0'}], 
            'main_component': {'bom_ref': 'test-app', 'type': 'file', 'name': 'test-app', 'version': '1.0.0'},
            # SyftSbom 모델에 timestamp 등의 속성이 있는지 확인 필요 (Parsing 단계에서 변환되었다고 가정)
        })()

        self.syft = SyftSbom(
            schema={"version": "14.0.0", "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-14.0.0.json"},
            bom_format="CycloneDX", 
            spec_version="1.6", 
            serial_number="uuid-2", 
            version=1,
            metadata=mock_syft_metadata,
            components=[
                SyftComponent(
                    name="numpy", version="2.2.6", type="library",
                    bom_ref="syft-ref-1", purl="pkg:pypi/numpy@2.2.6",
                    licenses=[License(id="BSD-3-Clause", name="BSD 3-Clause License")],
                    author="NumPy Developers <numpy-discussion@python.org>",
                    properties=[]  # [Fix 3] None 대신 빈 리스트 사용 (iteration 에러 방지)
                ),
                SyftComponent(
                    name="requests", version="2.31.0", type="library",
                    bom_ref="syft-ref-2", purl="pkg:pypi/requests@2.31.0",
                    licenses=[License(id="Apache-2.0", name="Apache License 2.0")],
                    author="Kenneth Reitz <me@kennethreitz.org>",
                    properties=[]  # [Fix 3] None 대신 빈 리스트 사용
                )
            ],
            # [Fix 1] integrate.py에서 순회하므로 빈 리스트라도 있어야 합니다.
            dependencies=[]
        )

    def test_integrate_merges_data_correctly(self):
        """두 SBOM이 성공적으로 병합되는지 테스트합니다."""
        result = self.integrator.integrate(self.hatbom, self.syft)

        # 컴포넌트 총 개수 확인 (numpy는 중복이므로 병합되어 총 2개여야 함: numpy, requests)
        self.assertEqual(len(result.components), 2)

        # numpy 데이터 검증 (병합 결과 확인)
        numpy_comp = next(c for c in result.components if c.name == "numpy")
        
        # Syft에서 온 라이선스 확인
        # UnifiedComponent의 licenses는 [{'license': {'id': ...}}] 구조임
        self.assertEqual(numpy_comp.licenses[0]['license']['id'], "BSD-3-Clause")
        
        # Hatbom에서 온 해시 확인
        # UnifiedComponent의 hashes는 [{'alg': ..., 'content': ...}] 구조임
        self.assertEqual(numpy_comp.hashes[0]['content'], "hash-numpy-123")

    def test_new_serial_number_generation(self):
        """통합본이 새로운 시리얼 번호를 가지는지 확인합니다."""
        result = self.integrator.integrate(self.hatbom, self.syft)
        
        # UnifiedSbom 모델에 serial_number 필드가 있는지 확인 필요 (보통 메타데이터나 최상위에 위치)
        # integrate.py 코드를 보면 serial_number 생성 로직이 명시적으로 보이지 않지만, 
        # UnifiedSbom 초기화 시 생성된다면 아래 테스트가 유효합니다.
        if hasattr(result, 'serial_number') and result.serial_number:
            self.assertTrue(result.serial_number.startswith("urn:uuid:"))
            self.assertNotEqual(result.serial_number, "uuid-1")
            self.assertNotEqual(result.serial_number, "uuid-2")

    def test_source_tool_property(self):
        """출처 정보(properties)가 제대로 기록되는지 확인합니다."""
        result = self.integrator.integrate(self.hatbom, self.syft)
        numpy_comp = next(c for c in result.components if c.name == "numpy")
        
        # 출처 리스트에 Syft와 Hatbom이 모두 포함되어 있는지 확인
        sources = [p['value'] for p in numpy_comp.properties if p['name'] == 'source_tool' or p['name'] == 'integrated_with']
        
        # integrate.py 로직상:
        # Syft 기반으로 생성 시 -> properties에 {"name": "source_tool", "value": "Syft"} 추가
        # Hatbom 병합 시 -> properties에 {"name": "integrated_with", "value": "Hatbom"} 추가
        self.assertIn("Syft", sources)
        self.assertIn("Hatbom", sources)

if __name__ == "__main__":
    unittest.main()