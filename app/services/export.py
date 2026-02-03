import json
from dataclasses import asdict
from typing import Dict, Any, Optional
from pathlib import Path

from app.models.unified_sbom import UnifiedSbom, UnifiedAuthor, UnifiedMetadataComponent

"""
export.py
해당 파일은 통합된 SBOM 데이터를 다양한 형식으로 내보내는 기능을 제공합니다.
주요기능:
1. UnifiedSbom 객체를 JSON 형식으로 변환합니다.
2. 변환된 데이터를 파일로 저장하거나 딕셔너리로 반환합니다.
3. CycloneDX 표준 형식에 맞게 필드명을 변환합니다.
"""


class SBOMExporter:
    def __init__(self, unified_sbom: UnifiedSbom):
        self.unified_sbom = unified_sbom

    def to_dict(self) -> Dict[str, Any]:
        """
        UnifiedSbom 객체를 CycloneDX 표준 형식의 딕셔너리로 변환합니다.
        Python snake_case 필드명을 CycloneDX camelCase로 변환합니다.
        """
        result = {
            "bomFormat": self.unified_sbom.bom_format,
            "specVersion": self.unified_sbom.spec_version,
            "serialNumber": self.unified_sbom.serial_number,
            "version": self.unified_sbom.version,
            "metadata": self._convert_metadata(),
            "components": self._convert_components(),
            "dependencies": self.unified_sbom.dependencies
        }
        return result

    def _convert_metadata(self) -> Dict[str, Any]:
        """메타데이터를 CycloneDX 형식으로 변환합니다."""
        metadata = self.unified_sbom.metadata
        if metadata is None:
            return {}

        result = {
            "timestamp": metadata.timestamp,
            "tools": metadata.tools
        }

        # Authors 변환
        if metadata.authors:
            result["authors"] = [
                self._convert_author(author) for author in metadata.authors
            ]

        # Component 변환
        if metadata.component:
            result["component"] = self._convert_metadata_component(metadata.component)

        return result

    def _convert_author(self, author: UnifiedAuthor) -> Dict[str, Optional[str]]:
        """UnifiedAuthor를 딕셔너리로 변환합니다."""
        author_dict = {}
        if author.name:
            author_dict["name"] = author.name
        if author.email:
            author_dict["email"] = author.email
        return author_dict

    def _convert_metadata_component(self, component: UnifiedMetadataComponent) -> Dict[str, Any]:
        """메타데이터의 메인 컴포넌트를 변환합니다."""
        result = {
            "name": component.name,
            "type": component.type,
            "bom-ref": component.bom_ref
        }
        if component.version:
            result["version"] = component.version
        if component.group:
            result["group"] = component.group
        if component.purl:
            result["purl"] = component.purl
        return result

    def _convert_components(self) -> list:
        """컴포넌트 목록을 CycloneDX 형식으로 변환합니다."""
        components = []
        for comp in self.unified_sbom.components:
            comp_dict = {
                "name": comp.name,
                "version": comp.version,
                "type": comp.type,
                "bom-ref": comp.bom_ref
            }

            # Optional 필드들
            if comp.purl:
                comp_dict["purl"] = comp.purl
            if comp.group:
                comp_dict["group"] = comp.group
            if comp.cpe:
                comp_dict["cpe"] = comp.cpe
            if comp.description:
                comp_dict["description"] = comp.description
            if comp.hashes:
                comp_dict["hashes"] = comp.hashes
            if comp.licenses:
                comp_dict["licenses"] = comp.licenses
            if comp.properties:
                comp_dict["properties"] = comp.properties
            
            # Authors 변환 (UnifiedAuthor 리스트 -> 딕셔너리 리스트)
            if comp.authors:
                comp_dict["authors"] = [
                    self._convert_author(author) for author in comp.authors
                ]

            components.append(comp_dict)
        return components

    def to_json(self, indent: int = 2) -> str:
        """
        UnifiedSbom 객체를 JSON 문자열로 변환합니다.
        
        Args:
            indent: JSON 들여쓰기 수준 (기본값: 2)
            
        Returns:
            JSON 형식의 문자열
        """
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def save_to_file(self, output_path: str, indent: int = 2) -> str:
        """
        UnifiedSbom 객체를 JSON 파일로 저장합니다.
        
        Args:
            output_path: 저장할 파일 경로
            indent: JSON 들여쓰기 수준 (기본값: 2)
            
        Returns:
            저장된 파일의 절대 경로
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=indent, ensure_ascii=False)
        
        print(f"[INFO] 통합 SBOM이 저장되었습니다: {path.absolute()}")
        return str(path.absolute())

    def get_summary(self) -> Dict[str, Any]:
        """
        통합 SBOM의 요약 정보를 반환합니다.
        """
        metadata = self.unified_sbom.metadata
        
        # 소스별 컴포넌트 수 계산
        syft_count = 0
        hatbom_count = 0
        integrated_count = 0
        
        for comp in self.unified_sbom.components:
            sources = [p.get("value") for p in comp.properties if p.get("name") == "source_tool"]
            integrated = [p.get("value") for p in comp.properties if p.get("name") == "integrated_with"]
            
            if "Syft" in sources:
                syft_count += 1
            if "Hatbom" in sources:
                hatbom_count += 1
            if integrated:
                integrated_count += 1

        return {
            "bom_format": self.unified_sbom.bom_format,
            "spec_version": self.unified_sbom.spec_version,
            "serial_number": self.unified_sbom.serial_number,
            "timestamp": metadata.timestamp if metadata else None,
            "total_components": len(self.unified_sbom.components),
            "total_dependencies": len(self.unified_sbom.dependencies),
            "components_from_syft": syft_count,
            "components_from_hatbom": hatbom_count,
            "integrated_components": integrated_count,
            "metadata_component": metadata.component.name if metadata and metadata.component else None
        }
