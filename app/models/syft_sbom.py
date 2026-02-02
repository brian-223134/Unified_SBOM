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

# components.author을 components.authors[] 리스트로 변환하기
- 기존의 components.author 필드의 경우 이름과 이메일 혹은 이름만 있는 경우가 있다. 이를 parsing해야 한다.
- 아래는 python3에서 제공하는 email.utils 모듈을 활용한 예시이다.

---
1. Parsing and Formatting a Single Email Address
import email.utils
import re

address_string = "Pepé Le Pew <pepe@example.com>"
real_name, email_address = email.utils.parseaddr(address_string)

print(f"Name: {real_name}")
print(f"Email: {email_address}")

# You can also format an address tuple back into a string:
formatted_address = email.utils.formataddr((real_name, email_address))
print(f"Formatted: {formatted_address}")

---
2. Extracting Email Address from a Block of Text
import re

text = "Contact us at support@example.com or sales-info@company.co.uk for details."

# A common regex pattern for finding email addresses (can vary in complexity)
# Note: A perfect regex for *all* valid emails is complex, but this handles most common cases
regex_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

found_emails = re.findall(regex_pattern, text)

print("Found emails:", found_emails)

---
3. 단일 저자 및 복수 저자를 동시에 처리하는 로직 예시

import email.utils
from typing import List, Dict, Optional

def parse_author_string(author_string: str) -> List[Dict[str, Optional[str]]]:
    """
    단일 또는 여러 명의 저자가 포함된 author 문자열을 파싱합니다.
    
    입력 예시:
    - 단일: "Alex Grönholm <alex.gronholm@nextday.fi>"
    - 여러명: "Filipe Laíns <lains@riseup.net>, Bernát Gábor <gaborjbernat@gmail.com>"
    
    반환: [{"name": "이름", "email": "이메일주소"}, ...]
    """
    if not author_string or not author_string.strip():
        return []
    
    # email.utils.getaddresses()는 쉼표로 구분된 여러 주소를 파싱할 수 있음
    # 리스트로 감싸서 전달해야 함
    parsed_addresses = email.utils.getaddresses([author_string])
    
    authors = []
    for name, email_addr in parsed_addresses:
        # 이름과 이메일이 모두 비어있으면 건너뜀
        if not name and not email_addr:
            continue
            
        authors.append({
            "name": name if name else None,
            "email": email_addr if email_addr else None
        })
    
    return authors


# 테스트
if __name__ == "__main__":
    # 단일 저자
    single_author = "Alex Grönholm <alex.gronholm@nextday.fi>"
    
    # 여러 저자
    multiple_authors = "Filipe Laíns <lains@riseup.net>, Bernát Gábor <gaborjbernat@gmail.com>, layday <layday@protonmail.com>, Henry Schreiner <henryschreineriii@gmail.com>"
    
    # 이메일만 있는 경우
    email_only = "test@example.com"
    
    # 이름만 있는 경우
    name_only = "John Doe"
    
    print("=== 단일 저자 ===")
    result = parse_author_string(single_author)
    for author in result:
        print(f"  Name: {author['name']}, Email: {author['email']}")
    
    print("\n=== 여러 저자 ===")
    result = parse_author_string(multiple_authors)
    for author in result:
        print(f"  Name: {author['name']}, Email: {author['email']}")
    
    print("\n=== 이메일만 ===")
    result = parse_author_string(email_only)
    for author in result:
        print(f"  Name: {author['name']}, Email: {author['email']}")
    
    print("\n=== 이름만 ===")
    result = parse_author_string(name_only)
    for author in result:
        print(f"  Name: {author['name']}, Email: {author['email']}")
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