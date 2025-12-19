# backend/app/services/ids.py
"""
Application-level Intrusion Detection System
Uses ML to detect attacks and anomalies
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from typing import List, Dict

class IntrusionDetectionSystem:
    """ML-based intrusion detection"""
    
    def __init__(self):
        self.model = IsolationForest(contamination=0.1)
        self.trained = False
    
    async def train_on_normal_traffic(self):
        """Train model on normal user behavior"""
        
        # Fetch historical normal behavior
        normal_logs = await self._get_normal_behavior_logs()
        
        # Extract features
        features = [self._extract_features(log) for log in normal_logs]
        
        # Train model
        self.model.fit(features)
        self.trained = True
    
    def _extract_features(self, log: Dict) -> List[float]:
        """Extract features from log entry"""
        
        return [
            log.get('request_count', 0),
            log.get('error_rate', 0),
            log.get('response_time_avg', 0),
            log.get('unique_endpoints', 0),
            log.get('data_volume', 0),
            self._time_of_day_score(log.get('timestamp')),
            self._geographic_anomaly_score(log.get('ip_address')),
        ]
    
    async def analyze_request(self, request_data: Dict) -> Dict:
        """Analyze request for intrusion indicators"""
        
        if not self.trained:
            await self.train_on_normal_traffic()
        
        features = self._extract_features(request_data)
        prediction = self.model.predict([features])[0]
        score = self.model.score_samples([features])[0]
        
        is_anomaly = prediction == -1
        
        if is_anomaly:
            return {
                "is_intrusion": True,
                "confidence": abs(score),
                "threat_level": self._calculate_threat_level(score),
                "recommended_action": "block" if score < -0.5 else "monitor"
            }
        
        return {
            "is_intrusion": False,
            "confidence": abs(score),
            "threat_level": "none"
        }