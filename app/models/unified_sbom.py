import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional

@dataclass
class UnifiedComponent:
    """
    Syft의 패키지 정보와 Hatbom의 파일 정보를 통합하여 저장하는 클래스 입니다.
    """
    name: str
    version: str
    type: str  # library, file, application 등
    bom_ref: str
    purl: Optional[str] = None
    group: Optional[str] = ""
    hashes: List[Dict[str, str]] = field(default_factory=list)  # Hatbom에서 주로 수집
    licenses: List[Dict[str, Any]] = field(default_factory=list) # Syft에서 주로 수집
    properties: List[Dict[str, str]] = field(default_factory=list) # 출처 및 추가 메타데이터
    description: Optional[str] = ""

@dataclass
class UnifiedSbom:
    """
    최종 통합본 SBOM을 정의하는 클래스 입니다.
    """
    bom_format: str = "CycloneDX"
    spec_version: str = "1.6"
    serial_number: str = field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    version: int = 1
    metadata: Dict[str, Any] = field(default_factory=dict)
    components: List[UnifiedComponent] = field(default_factory=list)
    dependencies: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        """객체 생성 후 기본 메타데이터 설정"""
        if not self.metadata:
            self.metadata = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": {
                    "components": [
                        {"name": "Quick-BOM-Integrator", "version": "1.0.0"}
                    ]
                }
            }

    def add_component(self, component: UnifiedComponent):
        self.components.append(component)