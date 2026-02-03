import json

"""
integrate.py
해당 파일은 Hatbom과 Syft 형식의 SBOM 데이터를 통합하는 기능을 제공합니다.
주요기능:
parse.py에서 파싱된 Hatbom과 Syft 데이터를 통합합니다.
1. Hatbom과 Syft 형식의 SBOM 데이터를 통합합니다.
    - 중복된 데이터를 검증하는 로직은 components에 대하여 진행합니다.
    - components 필드의 name을 통해 유사도를 측정합니다.
    - 유사도가 일정 기준 이상인 경우 중복으로 간주하고 하나의 데이터로 통합합니다. (주로 name 필드를 기준으로 하며 version까지 같은 경우 동일하다고 판단)
2. 통합된 데이터를 JSON 형식으로 반환합니다.
"""

import uuid
from datetime import datetime
from typing import List, Dict, Any
from app.models.hatbom_sbom import HatbomSbom
from app.models.syft_sbom import SyftSbom
from app.models.unified_sbom import (
    UnifiedSbom, 
    UnifiedComponent, 
    UnifiedAuthor, 
    UnifiedMetadata, 
    UnifiedMetadataComponent
)
from app.services.parse import parse_author_string

class SBOMIntegrator:
    def __init__(self):
        self.unified_sbom = UnifiedSbom()

    def integrate(self, hatbom: HatbomSbom, syft: SyftSbom) -> UnifiedSbom:
        """
        두 도구의 SBOM 객체를 받아 하나로 통합합니다.
        """
        print("[INFO] SBOM 통합 프로세스를 시작합니다.")
        
        # 0. 메타데이터 통합
        self._integrate_metadata(hatbom, syft)
        
        # 통합 컴포넌트를 저장할 딕셔너리 (Key: 식별자)
        merged_map: Dict[str, UnifiedComponent] = {}

        # 1. Syft 데이터를 기본 베이스로 설정 (패키지 정보 중심)
        for s_comp in syft.components:
            key = self._generate_key(s_comp.name, s_comp.version, s_comp.purl)
            
            # Syft의 author 문자열을 UnifiedAuthor 리스트로 변환
            authors = []
            if s_comp.author:
                parsed_authors = parse_author_string(s_comp.author)
                authors = [UnifiedAuthor(name=a.get("name"), email=a.get("email")) for a in parsed_authors]
            
            # Syft의 기존 properties를 가져오고 source_tool 추가
            syft_properties = [{"name": p.name, "value": p.value} for p in s_comp.properties]
            syft_properties.append({"name": "source_tool", "value": "Syft"})
            
            unified_comp = UnifiedComponent(
                name=s_comp.name,
                version=s_comp.version,
                type=s_comp.type,
                bom_ref=s_comp.bom_ref,
                purl=s_comp.purl,
                cpe=s_comp.cpe,
                licenses=[{"license": {"id": l.id, "name": l.name}} for l in s_comp.licenses],
                properties=syft_properties,
                authors=authors
            )
            merged_map[key] = unified_comp

        # 2. Hatbom 데이터를 병합 (파일 해시 정보 보완)
        for h_comp in hatbom.components:
            key = self._generate_key(h_comp.name, h_comp.version, h_comp.purl)
            
            if key in merged_map:
                # 이미 Syft에 존재하는 패키지라면 해시 정보만 추가
                existing = merged_map[key]
                existing.hashes.extend([{"alg": h.alg, "content": h.content} for h in h_comp.hashes])
                existing.properties.append({"name": "integrated_with", "value": "Hatbom"})
                # group 정보가 없으면 Hatbom에서 가져옴
                if not existing.group and h_comp.group:
                    existing.group = h_comp.group
            else:
                # Syft에는 없지만 Hatbom에만 있는 새로운 데이터라면 추가
                new_comp = UnifiedComponent(
                    name=h_comp.name,
                    version=h_comp.version,
                    type=h_comp.type,
                    bom_ref=h_comp.bom_ref,
                    purl=h_comp.purl,
                    group=h_comp.group,
                    hashes=[{"alg": h.alg, "content": h.content} for h in h_comp.hashes],
                    properties=[{"name": "source_tool", "value": "Hatbom"}]
                )
                merged_map[key] = new_comp

        # 3. 결과 객체 구성
        self.unified_sbom.components = list(merged_map.values())
        
        # 4. 의존성 정보 통합 (Hatbom의 dependencies 사용)
        self._integrate_dependencies(hatbom)
        
        print(f"[SUCCESS] 통합 완료: 총 {len(self.unified_sbom.components)} 개의 컴포넌트가 병합되었습니다.")
        return self.unified_sbom

    def _integrate_metadata(self, hatbom: HatbomSbom, syft: SyftSbom):
        """
        Hatbom과 Syft의 메타데이터를 통합합니다.
        """
        # 1. Authors 통합 (Hatbom + Syft tools의 author 정보)
        unified_authors = []
        # Hatbom의 authors 추가
        for author_dict in hatbom.metadata.authors:
            unified_authors.append(UnifiedAuthor(
                name=author_dict.get("name"),
                email=author_dict.get("email")
            ))
        # Syft tools.components의 author 정보 추가
        for tool in syft.metadata.tools:
            if tool.get("author"):
                # author 문자열을 파싱하여 추가
                parsed_authors = parse_author_string(tool.get("author"))
                for parsed in parsed_authors:
                    unified_authors.append(UnifiedAuthor(
                        name=parsed.get("name"),
                        email=parsed.get("email")
                    ))
        
        # 2. Tools 통합 (Syft + Hatbom + Quick-BOM-Integrator)
        tools_components = []
        # Syft 도구 정보 추가
        for tool in syft.metadata.tools:
            tools_components.append(tool)
        # Hatbom 도구 정보 추가 (있다면)
        tools_components.append({"name": "Hatbom", "version": "1.0.0"})
        # 통합 도구 정보 추가
        tools_components.append({"name": "Quick-BOM-Integrator", "version": "1.0.0"})
        
        # 3. Main Component 통합 (Hatbom 기준, 더 상세한 정보 보유)
        hatbom_comp = hatbom.metadata.component
        syft_comp = syft.metadata.main_component
        
        unified_meta_comp = UnifiedMetadataComponent(
            name=hatbom_comp.get("name") or syft_comp.get("name", ""),
            type=hatbom_comp.get("type") or syft_comp.get("type", "application"),
            bom_ref=hatbom_comp.get("bom-ref") or syft_comp.get("bom-ref", ""),
            version=hatbom_comp.get("version") or syft_comp.get("version", ""),
            group=hatbom_comp.get("group", ""),
            purl=hatbom_comp.get("purl")
        )
        
        # 4. UnifiedMetadata 생성
        self.unified_sbom.metadata = UnifiedMetadata(
            timestamp=hatbom.metadata.timestamp or syft.metadata.timestamp,
            authors=unified_authors,
            tools={"components": tools_components},
            component=unified_meta_comp
        )

    def _integrate_dependencies(self, hatbom: HatbomSbom):
        """
        의존성 정보를 통합합니다.
        """
        dependencies = []
        for dep in hatbom.dependencies:
            dependencies.append({
                "ref": dep.ref,
                "dependsOn": dep.depends_on
            })
        self.unified_sbom.dependencies = dependencies

    def _generate_key(self, name: str, version: str, purl: str = None) -> str:
        """컴포넌트 식별을 위한 고유 키 생성 (PURL 우선)"""
        if purl:
            return purl
        return f"{name}@{version}"

    def save_to_json(self, output_path: str):
        """통합된 결과를 JSON 파일로 저장"""
        import json
        from dataclasses import asdict
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(asdict(self.unified_sbom), f, indent=2, ensure_ascii=False)
        print(f"[INFO] 통합 SBOM이 저장되었습니다: {output_path}")

# 실행 예시
if __name__ == "__main__":
    # parse.py를 통해 얻은 객체들이 있다고 가정
    # integrator = SBOMIntegrator()
    # final_sbom = integrator.integrate(hatbom_obj, syft_obj)
    # integrator.save_to_json("integrated_sbom.json")
    pass