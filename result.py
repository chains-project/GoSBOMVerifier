from dataclasses import dataclass, field

@dataclass
class ModuleResult:
    name: str
    detected: bool
    confidence: float = 0.0     
    detail: str = ""            
    is_direct: bool = True      
@dataclass
class DiscoveredLib:
    # Discoved Library
    name: str
    match_rate: float           
    matched: int                 
    total_lib_funcs: int         
    name_matches: int           
    in_sbom: bool = False       

@dataclass
class VerificationResult:
    method: str                             
    mode: str = "sbom"                      
    # SBOM-iteration
    total_sbom_modules: int = 0
    identified_count: int = 0
    not_identified: list = field(default_factory=list)
    percentage: float = 0.0
    modules: list = field(default_factory=list)   
    unlisted: list = field(default_factory=list)  
    # Direct/indirect 
    total_direct: int = 0
    identified_direct: int = 0
    percentage_direct: float = 0.0
    total_indirect: int = 0
    identified_indirect: int = 0
    percentage_indirect: float = 0.0
    has_direct_info: bool = False
    # libdb in-DB-only
    in_db_count: int = 0
    percentage_in_db: float = 0.0
    # Discovery-mode 
    total_libs_in_db: int = 0                       
    discovered_count: int = 0                       
    discovered: list = field(default_factory=list)  
    match_threshold: float = 0.0                    
    name_match_min: int = 0                         
    adaptive_fallback_used: bool = False            
                                                    
                                                    
    # Results
    discovery_tp: int = 0                          
    discovery_fp: int = 0                           
    discovery_fn: int = 0                          
    discovery_precision: float = 0.0
    discovery_recall: float = 0.0
    discovery_f1: float = 0.0
    sbom_outside_db: int = 0                        
