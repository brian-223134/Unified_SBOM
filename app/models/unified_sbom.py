import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional


@dataclass
class UnifiedAuthor:
    """
    저자 정보를 저장하는 클래스입니다.
    Syft의 author 문자열을 파싱하여 name/email로 분리하거나,
    Hatbom의 authors 배열에서 가져온 정보를 저장합니다.
    """
    name: Optional[str] = None
    email: Optional[str] = None


@dataclass
class UnifiedMetadataComponent:
    """
    SBOM 메타데이터의 메인 컴포넌트 정보를 저장하는 클래스입니다.
    Hatbom과 Syft의 metadata.component를 통합합니다.
    """
    name: str
    type: str  # application, file 등
    bom_ref: str
    version: Optional[str] = ""
    group: Optional[str] = ""
    purl: Optional[str] = None


@dataclass
class UnifiedMetadata:
    """
    SBOM 메타데이터를 저장하는 클래스입니다.
    Hatbom과 Syft의 metadata를 통합합니다.
    """
    timestamp: str
    authors: List[UnifiedAuthor] = field(default_factory=list)  # Hatbom + Syft 저자 통합
    tools: Dict[str, Any] = field(default_factory=dict)  # 도구 정보 (components 배열 포함)
    component: Optional[UnifiedMetadataComponent] = None  # 메인 컴포넌트 정보


@dataclass
class UnifiedComponent:
    """
    Syft의 패키지 정보와 Hatbom의 파일 정보를 통합하여 저장하는 클래스입니다.
    """
    name: str
    version: str
    type: str  # library, file, application 등
    bom_ref: str
    purl: Optional[str] = None
    group: Optional[str] = ""
    hashes: List[Dict[str, str]] = field(default_factory=list)  # Hatbom에서 주로 수집
    licenses: List[Dict[str, Any]] = field(default_factory=list)  # Syft에서 주로 수집
    properties: List[Dict[str, str]] = field(default_factory=list)  # 출처 및 추가 메타데이터
    authors: List[UnifiedAuthor] = field(default_factory=list)  # Syft의 author를 파싱하여 저장 (deprecated author 대체)
    description: Optional[str] = ""
    cpe: Optional[str] = None  # Syft에서 제공하는 CPE


@dataclass
class UnifiedSbom:
    """
    최종 통합본 SBOM을 정의하는 클래스입니다.
    Hatbom과 Syft SBOM을 통합한 CycloneDX 형식의 SBOM입니다.
    """
    bom_format: str = "CycloneDX"
    spec_version: str = "1.6"
    serial_number: str = field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    version: int = 1
    metadata: Optional[UnifiedMetadata] = None
    components: List[UnifiedComponent] = field(default_factory=list)
    dependencies: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        """객체 생성 후 기본 메타데이터 설정"""   
        if self.metadata is None:
            self.metadata = UnifiedMetadata(
                timestamp=datetime.utcnow().isoformat() + "Z",
                authors=[],
                tools={
                    "components": [
                        {"name": "Quick-BOM-Integrator", "version": "1.0.0"}
                    ]
                },
                component=None
            )

    def add_component(self, component: UnifiedComponent):
        """컴포넌트를 추가합니다."""
        self.components.append(component)

    def add_author(self, author: UnifiedAuthor):
        """메타데이터에 저자를 추가합니다."""
        if self.metadata is not None:
            self.metadata.authors.append(author)

    def set_metadata_component(self, component: UnifiedMetadataComponent):
        """메타데이터의 메인 컴포넌트를 설정합니다."""
        if self.metadata is not None:
            self.metadata.component = component