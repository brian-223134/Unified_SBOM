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