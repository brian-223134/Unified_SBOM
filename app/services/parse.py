import os
import json
from typing import Any, Dict

"""
parse.py
해당 파일은 JSON 형식의 데이터를 파싱하는 기능을 제공합니다.
주요기능:
1. Hatbom, Syft 형식으로 작성된 JSON 데이터를 파싱합니다. (SBOM이 가지는 필드에 해당 값을 객체에 저장)
2. 파싱된 데이터를 임시 저장합니다.
"""

def parse_hatbom(data: Dict[str, Any]) -> Dict[str, Any]:
    '''
    Hatbom 형식은 다른 sbom 형식과는 다르게 sbom, count_file 이라는 wrapper가 존재합니다.
    해당 wrapper를 제거하고 내부의 sbom 데이터를 반환합니다.
    '''
    
    if "sbom" in data:
        return data["sbom"]
    else:
        raise ValueError("올바르지 않은 Hatbom 양식 입니다. iotcub 2.0에서 생성한 sbom인지 확인해주세요.")
    
    # count_file = components 개수
    if "count_file" in data:
        del data["count_file"] 
    
    