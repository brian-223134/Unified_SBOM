'''
hatbom으로 생성된 json 형식의 sbom을 파싱하여 객체로 반환하기 위한 파일
'''


class hatbom_sbom:
    def __init__(self, name, version, components):
        self.name = name
        self.version = version
        self.components = components

    def to_dict(self):
        return {
            "name": self.name,
            "version": self.version,
            "components": [component.to_dict() for component in self.components],
        }