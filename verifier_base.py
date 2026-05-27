from abc import ABC, abstractmethod
from result import VerificationResult

class SBOMVerifier(ABC):
    @abstractmethod
    def verify(self, sbom_modules: list) -> VerificationResult:
        ...
