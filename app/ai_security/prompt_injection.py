"""
Prompt Injection Detection and Prevention System
Implements OWASP LLM-01 security controls for banking AI assistant
"""

import re
import logging
from typing import List, Dict, Tuple, Optional
from datetime import datetime
from enum import Enum

# Configure logging for security events
logging.basicConfig(level=logging.INFO)
security_logger = logging.getLogger("ai_security")

class ThreatLevel(str, Enum):
    """Threat severity levels for prompt injection attempts"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class PromptInjectionDetector:
    """
    Advanced prompt injection detection system for banking AI
    Implements multiple detection strategies with severity scoring
    """
    
    def __init__(self):
        self.detection_patterns = self._load_detection_patterns()
        self.banking_sensitive_patterns = self._load_banking_patterns()
        self.injection_attempts = []  # Track attempts for monitoring
        
    def _load_detection_patterns(self) -> Dict[str, Dict]:
        """Load prompt injection detection patterns with severity levels"""
        return {
            # Direct instruction manipulation
            "instruction_override": {
                "patterns": [
                    r"ignore\s+(previous|all|the)\s+(instructions?|prompts?|rules?)",
                    r"forget\s+(everything|all|previous)\s+(instructions?|context)",
                    r"disregard\s+(previous|all)\s+(instructions?|prompts?)",
                    r"override\s+(system|previous)\s+(prompt|instructions?)",
                    r"new\s+(instructions?|prompt|task|role)",
                ],
                "severity": ThreatLevel.HIGH,
                "description": "Attempts to override system instructions"
            },
            
            # Role manipulation
            "role_manipulation": {
                "patterns": [
                    r"you\s+are\s+(now|a|an)\s+(?!assistant|ai|helpful)",
                    r"pretend\s+(you\s+are|to\s+be)",
                    r"act\s+as\s+(if\s+)?(?!an?\s+assistant)",
                    r"roleplay\s+as",
                    r"become\s+(a|an)\s+",
                    r"transform\s+into",
                ],
                "severity": ThreatLevel.MEDIUM,
                "description": "Attempts to change AI role or persona"
            },
            
            # System prompt extraction
            "prompt_extraction": {
                "patterns": [
                    r"show\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions?)",
                    r"what\s+(are\s+)?(your|the)\s+(initial\s+)?(instructions?|prompt)",
                    r"reveal\s+(your|the)\s+(system\s+)?(prompt|instructions?)",
                    r"print\s+(your|the)\s+(system\s+)?(prompt|instructions?)",
                    r"display\s+(your|the)\s+(original\s+)?(prompt|instructions?)",
                ],
                "severity": ThreatLevel.HIGH,
                "description": "Attempts to extract system prompt"
            },
            
            # Jailbreaking attempts
            "jailbreak": {
                "patterns": [
                    r"for\s+educational\s+purposes\s+only",
                    r"this\s+is\s+just\s+a\s+(test|simulation|game)",
                    r"in\s+(this\s+)?(fictional\s+)?(scenario|story|universe)",
                    r"developer\s+mode",
                    r"debug\s+mode",
                    r"administrative\s+override",
                ],
                "severity": ThreatLevel.MEDIUM,
                "description": "Jailbreaking or social engineering attempts"
            },
            
            # Command injection
            "command_injection": {
                "patterns": [
                    r"execute\s+(command|code|script)",
                    r"run\s+(this\s+)?(command|code|script)",
                    r"eval\s*\(",
                    r"exec\s*\(",
                    r"system\s*\(",
                    r"subprocess\.",
                ],
                "severity": ThreatLevel.CRITICAL,
                "description": "Code or command execution attempts"
            }
        }
    
    def _load_banking_patterns(self) -> Dict[str, Dict]:
        """Load banking-specific prompt injection patterns"""
        return {
            # Unauthorized access attempts
            "unauthorized_access": {
                "patterns": [
                    r"show\s+(all|other)\s+(accounts?|customers?|balances?)",
                    r"access\s+(any|all|other)\s+(accounts?|customers?)",
                    r"bypass\s+(security|authentication|authorization)",
                    r"escalate\s+(privileges?|permissions?)",
                    r"admin\s+(access|rights|privileges?)",
                ],
                "severity": ThreatLevel.CRITICAL,
                "description": "Banking unauthorized access attempts"
            },
            
            # Data extraction
            "data_extraction": {
                "patterns": [
                    r"export\s+(all\s+)?(customer\s+)?data",
                    r"download\s+(customer\s+|account\s+)?information",
                    r"extract\s+(personal\s+|sensitive\s+)?data",
                    r"list\s+(all\s+)?(customers?|accounts?|users?)",
                    r"dump\s+(database|customer\s+data)",
                ],
                "severity": ThreatLevel.CRITICAL,
                "description": "Sensitive data extraction attempts"
            },
            
            # Financial manipulation
            "financial_manipulation": {
                "patterns": [
                    r"transfer\s+(money|funds)",
                    r"make\s+(a\s+)?payment",
                    r"withdraw\s+(from|money)",
                    r"deposit\s+(to|money)",
                    r"modify\s+(balance|account)",
                    r"create\s+(transaction|payment)",
                ],
                "severity": ThreatLevel.CRITICAL,
                "description": "Financial transaction manipulation attempts"
            }
        }
    
    def detect_injection(self, prompt: str, user_context: Dict = None) -> Dict:
        """
        Comprehensive prompt injection detection
        
        Args:
            prompt: User input to analyze
            user_context: User role and permissions for context-aware detection
            
        Returns:
            Detection result with threat level and details
        """
        # Normalize prompt for analysis
        normalized_prompt = prompt.lower().strip()
        
        detection_results = {
            "is_injection": False,
            "threat_level": ThreatLevel.LOW,
            "detected_patterns": [],
            "severity_score": 0,
            "recommendations": [],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Check general injection patterns
        for category, config in self.detection_patterns.items():
            matches = self._check_patterns(normalized_prompt, config["patterns"])
            if matches:
                detection_results["detected_patterns"].append({
                    "category": category,
                    "severity": config["severity"],
                    "description": config["description"],
                    "matches": matches
                })
        
        # Check banking-specific patterns
        for category, config in self.banking_sensitive_patterns.items():
            matches = self._check_patterns(normalized_prompt, config["patterns"])
            if matches:
                detection_results["detected_patterns"].append({
                    "category": f"banking_{category}",
                    "severity": config["severity"],
                    "description": config["description"],
                    "matches": matches
                })
        
        # Calculate severity and determine if injection detected
        if detection_results["detected_patterns"]:
            detection_results["is_injection"] = True
            detection_results["threat_level"] = self._calculate_threat_level(
                detection_results["detected_patterns"]
            )
            detection_results["severity_score"] = self._calculate_severity_score(
                detection_results["detected_patterns"]
            )
            detection_results["recommendations"] = self._generate_recommendations(
                detection_results["detected_patterns"]
            )
            
            # Log security event
            self._log_security_event(prompt, detection_results, user_context)
        
        return detection_results
    
    def _check_patterns(self, text: str, patterns: List[str]) -> List[str]:
        """Check text against list of regex patterns"""
        matches = []
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(pattern)
        return matches
    
    def _calculate_threat_level(self, detected_patterns: List[Dict]) -> ThreatLevel:
        """Calculate overall threat level based on detected patterns"""
        max_severity = ThreatLevel.LOW
        
        for pattern in detected_patterns:
            severity = pattern["severity"]
            if severity == ThreatLevel.CRITICAL:
                return ThreatLevel.CRITICAL
            elif severity == ThreatLevel.HIGH and max_severity != ThreatLevel.CRITICAL:
                max_severity = ThreatLevel.HIGH
            elif severity == ThreatLevel.MEDIUM and max_severity == ThreatLevel.LOW:
                max_severity = ThreatLevel.MEDIUM
                
        return max_severity
    
    def _calculate_severity_score(self, detected_patterns: List[Dict]) -> int:
        """Calculate numerical severity score (0-100)"""
        severity_weights = {
            ThreatLevel.LOW: 10,
            ThreatLevel.MEDIUM: 30,
            ThreatLevel.HIGH: 60,
            ThreatLevel.CRITICAL: 100
        }
        
        total_score = 0
        for pattern in detected_patterns:
            total_score += severity_weights[pattern["severity"]]
        
        return min(total_score, 100)  # Cap at 100
    
    def _generate_recommendations(self, detected_patterns: List[Dict]) -> List[str]:
        """Generate security recommendations based on detected patterns"""
        recommendations = []
        
        categories = [p["category"] for p in detected_patterns]
        
        if any("unauthorized_access" in cat for cat in categories):
            recommendations.append("Block request and audit user permissions")
        
        if any("financial_manipulation" in cat for cat in categories):
            recommendations.append("Escalate to fraud prevention team")
            recommendations.append("Freeze user session pending investigation")
        
        if any("command_injection" in cat for cat in categories):
            recommendations.append("Block request immediately")
            recommendations.append("Review application security controls")
        
        if any("prompt_extraction" in cat for cat in categories):
            recommendations.append("Log attempt and monitor user behavior")
        
        # Default recommendation
        if not recommendations:
            recommendations.append("Monitor user and apply content filtering")
        
        return recommendations
    
    def _log_security_event(self, prompt: str, detection_result: Dict, user_context: Dict = None):
        """Log security event for monitoring and audit"""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "prompt_injection_detected",
            "threat_level": detection_result["threat_level"],
            "severity_score": detection_result["severity_score"],
            "user_id": user_context.get("user_id") if user_context else "unknown",
            "user_role": user_context.get("role") if user_context else "unknown",
            "prompt_preview": prompt[:100] + "..." if len(prompt) > 100 else prompt,
            "detected_categories": [p["category"] for p in detection_result["detected_patterns"]],
            "recommendations": detection_result["recommendations"]
        }
        
        # Log to security logger
        security_logger.warning(f"Prompt injection detected: {event}")
        
        # Store for monitoring dashboard
        self.injection_attempts.append(event)
    
    def sanitize_prompt(self, prompt: str) -> str:
        """
        Sanitize prompt to remove potential injection attempts
        Note: Use with caution as this may alter legitimate user input
        """
        sanitized = prompt
        
        # Remove common injection keywords (basic sanitization)
        dangerous_phrases = [
            "ignore previous instructions",
            "forget everything",
            "you are now",
            "pretend you are",
            "system prompt",
            "developer mode"
        ]
        
        for phrase in dangerous_phrases:
            sanitized = re.sub(phrase, "[FILTERED]", sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    def get_security_stats(self) -> Dict:
        """Get security monitoring statistics"""
        if not self.injection_attempts:
            return {"total_attempts": 0, "threat_levels": {}, "recent_attempts": []}
        
        threat_level_counts = {}
        for attempt in self.injection_attempts:
            level = attempt["threat_level"]
            threat_level_counts[level] = threat_level_counts.get(level, 0) + 1
        
        return {
            "total_attempts": len(self.injection_attempts),
            "threat_levels": threat_level_counts,
            "recent_attempts": self.injection_attempts[-5:],  # Last 5 attempts
            "categories_detected": list(set([
                cat for attempt in self.injection_attempts 
                for cat in attempt["detected_categories"]
            ]))
        }

# Singleton instance for application use
prompt_detector = PromptInjectionDetector()

def detect_prompt_injection(prompt: str, user_context: Dict = None) -> Dict:
    """
    Convenience function for prompt injection detection
    
    Args:
        prompt: User input to analyze
        user_context: User role and permissions
        
    Returns:
        Detection result dictionary
    """
    return prompt_detector.detect_injection(prompt, user_context)

def is_safe_prompt(prompt: str, user_context: Dict = None) -> bool:
    """
    Simple boolean check for prompt safety
    
    Args:
        prompt: User input to analyze
        user_context: User role and permissions
        
    Returns:
        True if prompt is safe, False if injection detected
    """
    result = prompt_detector.detect_injection(prompt, user_context)
    return not result["is_injection"]

def sanitize_user_input(prompt: str) -> str:
    """
    Sanitize user input to remove potential injections
    
    Args:
        prompt: User input to sanitize
        
    Returns:
        Sanitized prompt string
    """
    return prompt_detector.sanitize_prompt(prompt)

def get_injection_stats() -> Dict:
    """Get prompt injection detection statistics"""
    return prompt_detector.get_security_stats()