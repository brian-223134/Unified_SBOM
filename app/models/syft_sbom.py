'''
[사용 예시]
import json

# 파일 로드
with open('transformers_syft_sbom.json', 'r', encoding='utf-8') as f:
    syft_data = json.load(f)

# 객체화
syft_sbom = SyftSbom.from_json(syft_data)

# 데이터 탐색 예시: 특정 파일의 경로(property) 찾기
for comp in syft_sbom.components:
    if comp.name == "anyio":
        paths = [p.value for p in comp.properties if "location" in p.name]
        print(f"Package: {comp.name}, Version: {comp.version}")
        print(f"Locations: {paths}")
'''

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

@dataclass
class Property:
    name: str
    value: str

@dataclass
class License:
    id: Optional[str] = None
    name: Optional[str] = None

@dataclass
class Component:
    bom_ref: str
    type: str
    name: str
    version: str
    cpe: Optional[str] = None
    purl: Optional[str] = None
    author: Optional[str] = None
    licenses: List[License] = field(default_factory=list)
    properties: List[Property] = field(default_factory=list)

@dataclass
class Metadata:
    timestamp: str
    tools: List[Dict[str, str]]
    main_component: Dict[str, str]

@dataclass
class SyftSbom:
    schema: str
    bom_format: str
    spec_version: str
    serial_number: str
    version: int
    metadata: Metadata
    components: List[Component] = field(default_factory=list)

    @classmethod
    def from_json(cls, data: Dict[str, Any]):
        """Syft JSON 데이터를 받아 SyftSbom 객체로 변환"""
        
        # 1. Metadata 파싱
        metadata_raw = data.get('metadata', {})
        tools_list = metadata_raw.get('tools', {}).get('components', [])
        metadata_obj = Metadata(
            timestamp=metadata_raw.get('timestamp'),
            tools=tools_list,
            main_component=metadata_raw.get('component', {})
        )

        # 2. Components 파싱
        components_list = []
        for c in data.get('components', []):
            # 라이선스 추출
            licenses = []
            for l in c.get('licenses', []):
                lic_node = l.get('license', {})
                licenses.append(License(
                    id=lic_node.get('id'),
                    name=lic_node.get('name')
                ))
            
            # 속성(properties) 추출
            props = [Property(name=p['name'], value=p['value']) for p in c.get('properties', [])]
            
            components_list.append(Component(
                bom_ref=c.get('bom-ref'),
                type=c.get('type'),
                name=c.get('name'),
                version=c.get('version'),
                cpe=c.get('cpe'),
                purl=c.get('purl'),
                author=c.get('author'),
                licenses=licenses,
                properties=props
            ))

        return cls(
            schema=data.get('$schema'),
            bom_format=data.get('bomFormat'),
            spec_version=data.get('specVersion'),
            serial_number=data.get('serialNumber'),
            version=data.get('version'),
            metadata=metadata_obj,
            components=components_list
        )