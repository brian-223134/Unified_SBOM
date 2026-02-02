import unittest
from app.models.hatbom_sbom import HatbomSbom, Component as HatComponent, Hash
from app.models.syft_sbom import SyftSbom, Component as SyftComponent, License
from app.models.unified_sbom import UnifiedSbom
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
        self.hatbom = HatbomSbom(
            bom_format="CycloneDX", spec_version="1.4", serial_number="uuid-1", version=1,
            metadata=None, components=[
                HatComponent(
                    name="numpy", version="2.2.6", type="file", 
                    bom_ref="pkg:pypi/numpy@2.2.6", purl="pkg:pypi/numpy@2.2.6",
                    hashes=[Hash(alg="MD5", content="hash-numpy-123")]
                )
            ]
        )

        # 2. 가상 Syft 데이터 생성 (라이선스 정보 위주)
        self.syft = SyftSbom(
            schema="...", bom_format="CycloneDX", spec_version="1.6", serial_number="uuid-2", version=1,
            metadata=type('obj', (object,), {'timestamp': '2026-01-29', 'tools': [], 'main_component': {}}),
            components=[
                SyftComponent(
                    name="numpy", version="2.2.6", type="library",
                    bom_ref="syft-ref-1", purl="pkg:pypi/numpy@2.2.6",
                    licenses=[License(id="BSD-3-Clause", name="BSD 3-Clause License")]
                ),
                SyftComponent(
                    name="requests", version="2.31.0", type="library",
                    bom_ref="syft-ref-2", purl="pkg:pypi/requests@2.31.0",
                    licenses=[License(id="Apache-2.0", name="Apache License 2.0")]
                )
            ]
        )

    def test_integrate_merges_data_correctly(self):
        """두 SBOM이 성공적으로 병합되는지 테스트합니다."""
        result = self.integrator.integrate(self.hatbom, self.syft)

        # 컴포넌트 총 개수 확인 (numpy는 중복이므로 2개가 되어야 함)
        self.assertEqual(len(result.components), 2)

        # numpy 데이터 검증 (병합 결과 확인)
        numpy_comp = next(c for c in result.components if c.name == "numpy")
        
        # Syft에서 온 라이선스 확인
        self.assertEqual(numpy_comp.licenses[0]['license']['id'], "BSD-3-Clause")
        
        # Hatbom에서 온 해시 확인
        self.assertEqual(numpy_comp.hashes[0]['content'], "hash-numpy-123")

    def test_new_serial_number_generation(self):
        """통합본이 새로운 시리얼 번호를 가지는지 확인합니다."""
        result = self.integrator.integrate(self.hatbom, self.syft)
        
        self.assertTrue(result.serial_number.startswith("urn:uuid:"))
        self.assertNotEqual(result.serial_number, "uuid-1")
        self.assertNotEqual(result.serial_number, "uuid-2")

    def test_source_tool_property(self):
        """출처 정보(properties)가 제대로 기록되는지 확인합니다."""
        result = self.integrator.integrate(self.hatbom, self.syft)
        numpy_comp = next(c for c in result.components if c.name == "numpy")
        
        # 출처 리스트에 Syft와 Hatbom이 모두 포함되어 있는지 확인
        sources = [p['value'] for p in numpy_comp.properties]
        self.assertIn("Syft", sources)
        self.assertIn("Hatbom", sources)

if __name__ == "__main__":
    unittest.main()