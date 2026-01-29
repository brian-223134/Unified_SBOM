

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