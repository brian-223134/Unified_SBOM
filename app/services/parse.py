import os
import json
from typing import Any, Dict, Optional, Union
from models.hatbom_sbom import HatbomSbom
from models.syft_sbom import SyftSbom

"""
parse.py
해당 파일은 JSON 형식의 데이터를 파싱하는 기능을 제공합니다.
주요기능:
1. Hatbom, Syft 형식으로 작성된 JSON 데이터를 파싱합니다. (SBOM이 가지는 필드에 해당 값을 객체에 저장)
2. 파싱된 데이터를 임시 저장합니다.

[사용 예시]
if __name__ == "__main__":
    parser = SBOMParser()
    
    # 예: Syft 파일 파싱
    # sy_obj = parser.parse("transformers_syft_sbom.json")
    
    # 예: Hatbom 파일 파싱
    # hat_obj = parser.parse("hatbom_input.json")
"""

class SBOMParser:
    def __init__(self):
        # 파싱된 데이터를 임시 저장하는 공간
        self.parsed_data: Optional[Union[HatbomSbom, SyftSbom]] = None

    def parse(self, file_path: str) -> Union[HatbomSbom, SyftSbom]:
        """
        JSON 파일을 읽어 도구 형식을 판별하고 객체로 변환합니다.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"파일을 찾을 수 없습니다: {file_path}")

        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # 도구 형식 판별 로직
        if self._is_syft(data):
            print(f"[INFO] Syft 형식의 SBOM을 파싱합니다: {file_path}")
            self.parsed_data = SyftSbom.from_json(data)
        else:
            print(f"[INFO] Hatbom 형식의 SBOM을 파싱합니다: {file_path}")
            self.parsed_data = HatbomSbom.from_json(data)

        return self.parsed_data

    def _is_syft(self, data: Dict[str, Any]) -> bool:
        """
        Syft으로 생성된 SBOM인지 확인합니다.
        (Syft은 보통 $schema 필드를 가지거나 metadata.tools.components에 syft 정보가 있음)
        """
        if "$schema" in data and "cyclonedx" in data["$schema"].lower():
            # Syft 특유의 metadata 구조 확인
            metadata = data.get("metadata", {})
            tools = metadata.get("tools", {})
            # CycloneDX 1.5+ (Syft 1.40+) 구조 확인
            if isinstance(tools, dict) and "components" in tools:
                for tool in tools["components"]:
                    if tool.get("name") == "syft":
                        return True
        return False

    def get_temporary_data(self) -> Optional[Union[HatbomSbom, SyftSbom]]:
        """임시 저장된 파싱 데이터를 반환합니다."""
        return self.parsed_data

