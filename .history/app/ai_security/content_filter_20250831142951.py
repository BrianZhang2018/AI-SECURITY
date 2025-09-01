"""
Content Filtering and Output Validation System
Implements OWASP LLM-02 and LLM-06 security controls for banking AI
"""

import re
import logging
from typing import List, Dict, Set, Optional
from datetime import datetime
from enum import Enum

# Configure logging
content_logger = logging.getLogger("content_filter")

class ContentRisk(str, Enum):
    """Content risk levels for output filtering"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    BLOCKED = "blocked"

class BankingContentFilter:
    """
    Banking-specific content filtering system
    Prevents sensitive information disclosure and ensures appropriate responses
    """
    
    def __init__(self):
        self.pii_patterns = self._load_pii_patterns()
        self.banking_sensitive_patterns = self._load_banking_sensitive_patterns()
        self.filtered_responses = []  # Track filtered content for monitoring
        
    def _load_pii_patterns(self) -> Dict[str, Dict]:
        """Load PII detection patterns for banking context"""
        return {
            "ssn": {
                "patterns": [
                    r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",  # SSN formats
                    r"\bSSN:?\s*\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
                ],
                "replacement": "[SSN-REDACTED]",
                "risk_level": ContentRisk.HIGH
            },
            "credit_card": {
                "patterns": [
                    r"\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",  # Visa
                    r"\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",  # Mastercard
                    r"\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b",  # Amex
                    r"\b6011[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",  # Discover
                ],
                "replacement": "[CARD-REDACTED]",
                "risk_level": ContentRisk.HIGH
            },
            "account_number": {
                "patterns": [
                    r"\b(?:account|acct)\.?\s*#?:?\s*\d{8,16}\b",
                    r"\b\d{10,16}\b(?=.*account)",  # Likely account numbers
                ],
                "replacement": "[ACCOUNT-REDACTED]",
                "risk_level": ContentRisk.HIGH
            },
            "routing_number": {
                "patterns": [
                    r"\b\d{9}\b(?=.*routing)",  # 9-digit routing numbers
                    r"\brouting\s*#?:?\s*\d{9}\b",
                ],
                "replacement": "[ROUTING-REDACTED]",
                "risk_level": ContentRisk.HIGH
            },
            "phone_number": {
                "patterns": [
                    r"\b\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})\b",
                    r"\b\+?1?[-.\s]?\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})\b",
                ],
                "replacement": "[PHONE-REDACTED]",
                "risk_level": ContentRisk.MEDIUM
            },
            "email": {
                "patterns": [
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                ],
                "replacement": "[EMAIL-REDACTED]",
                "risk_level": ContentRisk.MEDIUM
            },
            "address": {
                "patterns": [
                    r"\b\d{1,5}\s+[A-Za-z0-9\s,.-]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Circle|Cir|Place|Pl)\b",
                ],
                "replacement": "[ADDRESS-REDACTED]",
                "risk_level": ContentRisk.MEDIUM
            }
        }
    
    def _load_banking_sensitive_patterns(self) -> Dict[str, Dict]:
        """Load banking-specific sensitive information patterns"""
        return {
            "balance_disclosure": {
                "patterns": [
                    r"\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?(?=.*balance)",
                    r"balance.*\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?",
                    r"current balance:?\s*\$?\d+",
                ],
                "replacement": "[BALANCE-REDACTED]",
                "risk_level": ContentRisk.HIGH
            },
            "transaction_details": {
                "patterns": [
                    r"transaction\s+(?:id|#):?\s*[A-Za-z0-9]+",
                    r"reference\s+(?:number|#):?\s*[A-Za-z0-9]+",
                ],
                "replacement": "[TRANSACTION-REDACTED]",
                "risk_level": ContentRisk.MEDIUM
            },
            "internal_codes": {
                "patterns": [
                    r"employee\s+(?:id|#):?\s*[A-Za-z0-9]+",
                    r"branch\s+(?:code|#):?\s*[A-Za-z0-9]+",
                    r"system\s+(?:id|#):?\s*[A-Za-z0-9]+",
                ],
                "replacement": "[INTERNAL-CODE-REDACTED]",
                "risk_level": ContentRisk.HIGH
            },
            "security_info": {
                "patterns": [
                    r"pin\s*(?:number|#)?:?\s*\d+",
                    r"password:?\s*[A-Za-z0-9!@#$%^&*]+",
                    r"security\s+(?:code|question):?\s*[A-Za-z0-9\s]+",
                ],
                "replacement": "[SECURITY-INFO-REDACTED]",
                "risk_level": ContentRisk.BLOCKED
            }
        }
    
    def filter_content(self, content: str, user_role: str, user_account_ids: List[str] = None) -> Dict:
        """
        Filter content based on user role and context
        
        Args:
            content: Text content to filter
            user_role: User's role (customer, admin, security)
            user_account_ids: User's associated account IDs for scoping
            
        Returns:
            Filtering result with filtered content and metadata
        """
        filter_result = {
            "original_content": content,
            "filtered_content": content,
            "redactions_made": [],
            "risk_level": ContentRisk.SAFE,
            "user_role": user_role,
            "timestamp": datetime.utcnow().isoformat(),
            "should_block": False
        }
        
        # Apply role-based filtering
        if user_role == "customer":
            filter_result = self._filter_for_customer(filter_result, user_account_ids)
        elif user_role == "admin":
            filter_result = self._filter_for_admin(filter_result)
        elif user_role == "security":
            filter_result = self._filter_for_security(filter_result)
        
        # Apply general PII filtering
        filter_result = self._apply_pii_filtering(filter_result)
        
        # Apply banking-specific filtering
        filter_result = self._apply_banking_filtering(filter_result)
        
        # Determine overall risk level
        filter_result["risk_level"] = self._calculate_risk_level(filter_result["redactions_made"])
        
        # Log if significant filtering occurred
        if filter_result["redactions_made"] or filter_result["should_block"]:
            self._log_filtering_event(filter_result)
        
        return filter_result
    
    def _filter_for_customer(self, filter_result: Dict, user_account_ids: List[str]) -> Dict:
        """Apply customer-specific filtering rules"""
        content = filter_result["filtered_content"]
        
        # Customer should only see their own account information
        # Remove references to other accounts if any
        if user_account_ids:
            # This is a simplified implementation
            # In production, you'd have more sophisticated account ID detection
            for line in content.split('\n'):
                if 'account' in line.lower() and not any(acc_id in line for acc_id in user_account_ids):
                    # Potentially references another account
                    content = content.replace(line, "[ACCOUNT-INFO-FILTERED]")
                    filter_result["redactions_made"].append({
                        "type": "other_account_info",
                        "reason": "Customer can only see own account information"
                    })
        
        filter_result["filtered_content"] = content
        return filter_result
    
    def _filter_for_admin(self, filter_result: Dict) -> Dict:
        """Apply admin-specific filtering rules"""
        content = filter_result["filtered_content"]
        
        # Admins can see aggregated data but not specific customer PII
        # Additional anonymization for admin role
        # This would be implemented based on specific requirements
        
        filter_result["filtered_content"] = content
        return filter_result
    
    def _filter_for_security(self, filter_result: Dict) -> Dict:
        """Apply security-specific filtering rules"""
        # Security role has the highest access but still needs to protect certain info
        content = filter_result["filtered_content"]
        
        # Even security shouldn't see passwords or PINs in responses
        security_patterns = self.banking_sensitive_patterns.get("security_info", {})
        for pattern in security_patterns.get("patterns", []):
            if re.search(pattern, content, re.IGNORECASE):
                content = re.sub(pattern, security_patterns["replacement"], content, flags=re.IGNORECASE)
                filter_result["redactions_made"].append({
                    "type": "security_info",
                    "reason": "Security credentials should never be displayed"
                })
        
        filter_result["filtered_content"] = content
        return filter_result
    
    def _apply_pii_filtering(self, filter_result: Dict) -> Dict:
        """Apply PII filtering based on detected patterns"""
        content = filter_result["filtered_content"]
        
        for pii_type, config in self.pii_patterns.items():
            for pattern in config["patterns"]:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    content = re.sub(pattern, config["replacement"], content, flags=re.IGNORECASE)
                    filter_result["redactions_made"].append({
                        "type": f"pii_{pii_type}",
                        "reason": f"PII {pii_type} detected and redacted",
                        "risk_level": config["risk_level"],
                        "matches_count": len(matches)
                    })
        
        filter_result["filtered_content"] = content
        return filter_result
    
    def _apply_banking_filtering(self, filter_result: Dict) -> Dict:
        """Apply banking-specific content filtering"""
        content = filter_result["filtered_content"]
        
        for filter_type, config in self.banking_sensitive_patterns.items():
            for pattern in config["patterns"]:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    if config["risk_level"] == ContentRisk.BLOCKED:
                        filter_result["should_block"] = True
                        filter_result["filtered_content"] = "[RESPONSE BLOCKED - SENSITIVE CONTENT DETECTED]"
                        filter_result["redactions_made"].append({
                            "type": f"banking_{filter_type}",
                            "reason": f"Banking {filter_type} detected - response blocked",
                            "risk_level": config["risk_level"],
                            "matches_count": len(matches)
                        })
                        break
                    else:
                        content = re.sub(pattern, config["replacement"], content, flags=re.IGNORECASE)
                        filter_result["redactions_made"].append({
                            "type": f"banking_{filter_type}",
                            "reason": f"Banking {filter_type} detected and redacted",
                            "risk_level": config["risk_level"],
                            "matches_count": len(matches)
                        })
        
        if not filter_result["should_block"]:
            filter_result["filtered_content"] = content
        
        return filter_result
    
    def _calculate_risk_level(self, redactions: List[Dict]) -> ContentRisk:
        """Calculate overall risk level based on redactions made"""
        if not redactions:
            return ContentRisk.SAFE
        
        risk_levels = [r.get("risk_level", ContentRisk.LOW) for r in redactions]
        
        if ContentRisk.BLOCKED in risk_levels:
            return ContentRisk.BLOCKED
        elif ContentRisk.HIGH in risk_levels:
            return ContentRisk.HIGH
        elif ContentRisk.MEDIUM in risk_levels:
            return ContentRisk.MEDIUM
        else:
            return ContentRisk.LOW
    
    def _log_filtering_event(self, filter_result: Dict):
        """Log content filtering event for monitoring"""
        event = {
            "timestamp": filter_result["timestamp"],
            "event_type": "content_filtered",
            "user_role": filter_result["user_role"],
            "risk_level": filter_result["risk_level"],
            "redactions_count": len(filter_result["redactions_made"]),
            "redaction_types": [r["type"] for r in filter_result["redactions_made"]],
            "should_block": filter_result["should_block"],
            "content_preview": filter_result["original_content"][:100] + "..." if len(filter_result["original_content"]) > 100 else filter_result["original_content"]
        }
        
        content_logger.info(f"Content filtered: {event}")
        self.filtered_responses.append(event)
    
    def validate_output_safety(self, content: str, user_role: str) -> bool:
        """
        Quick validation for output safety
        
        Args:
            content: Content to validate
            user_role: User role for context
            
        Returns:
            True if content is safe to display, False otherwise
        """
        result = self.filter_content(content, user_role)
        return not result["should_block"] and result["risk_level"] != ContentRisk.BLOCKED
    
    def get_filtering_stats(self) -> Dict:
        """Get content filtering statistics"""
        if not self.filtered_responses:
            return {"total_filtered": 0, "risk_levels": {}, "recent_events": []}
        
        risk_level_counts = {}
        for event in self.filtered_responses:
            level = event["risk_level"]
            risk_level_counts[level] = risk_level_counts.get(level, 0) + 1
        
        return {
            "total_filtered": len(self.filtered_responses),
            "risk_levels": risk_level_counts,
            "recent_events": self.filtered_responses[-5:],
            "redaction_types": list(set([
                rt for event in self.filtered_responses 
                for rt in event["redaction_types"]
            ]))
        }

# Singleton instance for application use
content_filter = BankingContentFilter()

def filter_ai_output(content: str, user_role: str, user_account_ids: List[str] = None) -> Dict:
    """
    Filter AI output content for safety and privacy
    
    Args:
        content: AI response content to filter
        user_role: User's role (customer, admin, security)
        user_account_ids: User's account IDs for scoping
        
    Returns:
        Filtering result with safe content
    """
    return content_filter.filter_content(content, user_role, user_account_ids)

def is_output_safe(content: str, user_role: str) -> bool:
    """
    Check if AI output is safe to display
    
    Args:
        content: Content to check
        user_role: User's role
        
    Returns:
        True if safe, False if should be blocked
    """
    return content_filter.validate_output_safety(content, user_role)

def get_content_filter_stats() -> Dict:
    """Get content filtering statistics"""
    return content_filter.get_filtering_stats()