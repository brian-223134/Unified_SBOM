'''
- hatbom으로 생성된 json 형식의 sbom을 파싱하여 객체로 반환하기 위한 파일
- hatbom 규격(구성 필드)
1. bomFormat
2. specVersion
3. serialNumber
4. version
5. metadata: 하위에 timestamp, authors, component 존재
5.1 timestamp
5.2 authors: array로 각 element가 object이다.
5.3 component: group, name, version, type, bom-ref, purl로 구성됨.
6. dependencies: array로 각 element가 object이다.
*6. object: ref, dependsOn으로 이루어져 있다. dependsOn도 array로 각 element는 string이다.
7. components: array로 각 element가 object이다.
*7. object: group, name, version, type, bom-ref, purl, hashes로 이루어져 있다. hashes도 array로 각 element는 object이다.
**7. hashes의 object: alg, content로 이루어져있다.

[사용 예시]
import json

# JSON 문자열 또는 로드된 딕셔너리
json_data = { ... } # 제공해주신 데이터

# 객체 생성
sbom_obj = HatbomSbom.from_json(json_data)

# 데이터 접근 예시
print(f"BOM Format: {sbom_obj.bom_format}")
print(f"Total Components: {len(sbom_obj.components)}")

# 특정 컴포넌트의 해시 값 출력
for comp in sbom_obj.components:
    if comp.name == "tpu":
        print(f"TPU File MD5: {comp.hashes[0].content}")
'''

from dataclasses import dataclass, field
from typing import List, Optional, Dict

@dataclass
class Hash:
    alg: str
    content: str

@dataclass
class Component:
    name: str
    version: str
    type: str
    bom_ref: str
    purl: str
    group: str = ""
    hashes: List[Hash] = field(default_factory=list)

@dataclass
class Dependency:
    ref: str
    depends_on: List[str] = field(default_factory=list)

@dataclass
class Metadata:
    timestamp: str
    authors: List[Dict[str, str]]
    component: Dict[str, str]  # 메인 컴포넌트 정보

@dataclass
class HatbomSbom:
    bom_format: str
    spec_version: str
    serial_number: str
    version: int
    metadata: Metadata
    components: List[Component] = field(default_factory=list)
    dependencies: List[Dependency] = field(default_factory=list)
    file_count: int = 0

    @classmethod
    def from_json(cls, data: Dict):
        """JSON 데이터를 받아 클래스 객체로 변환하는 팩토리 메서드"""
        
        # 1. Metadata 파싱
        metadata = Metadata(
            timestamp=data['metadata'].get('timestamp'),
            authors=data['metadata'].get('authors', []),
            component=data['metadata'].get('component', {})
        )

        # 2. Components 파싱
        components = []
        for c in data.get('components', []):
            hashes = [Hash(alg=h['alg'], content=h['content']) for h in c.get('hashes', [])]
            components.append(Component(
                group=c.get('group', ""),
                name=c.get('name'),
                version=c.get('version'),
                type=c.get('type'),
                bom_ref=c.get('bom-ref'),
                purl=c.get('purl'),
                hashes=hashes
            ))

        # 3. Dependencies 파싱
        dependencies = []
        for d in data.get('dependencies', []):
            dependencies.append(Dependency(
                ref=d.get('ref'),
                depends_on=d.get('dependsOn', [])
            ))

        return cls(
            bom_format=data.get('bomFormat'),
            spec_version=data.get('specVersion'),
            serial_number=data.get('serialNumber'),
            version=data.get('version'),
            metadata=metadata,
            components=components,
            dependencies=dependencies,
            file_count=data.get('file_count', 0)
        )