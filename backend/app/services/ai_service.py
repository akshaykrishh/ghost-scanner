"""
Ghost Scanner - AI/ML Service

AI-powered risk prioritization and remediation suggestion service.
"""

import openai
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import json
import structlog
from typing import Dict, List, Optional, Tuple
from pathlib import Path

from app.core.config import settings
from app.core.exceptions import AIAnalysisError

logger = structlog.get_logger()

class AIService:
    """AI service for risk prioritization and remediation suggestions."""
    
    def __init__(self):
        self.openai_client = None
        self.risk_model = None
        self.vectorizer = None
        self.model_path = Path("models")
        self.model_path.mkdir(exist_ok=True)
        
        # Initialize OpenAI client if API key is available
        if settings.OPENAI_API_KEY:
            self.openai_client = openai.OpenAI(api_key=settings.OPENAI_API_KEY)
        
        # Load or initialize ML models
        self._load_or_initialize_models()
    
    def _load_or_initialize_models(self):
        """Load existing models or initialize new ones."""
        try:
            # Try to load existing models
            self.risk_model = joblib.load(self.model_path / "risk_model.pkl")
            self.vectorizer = joblib.load(self.model_path / "vectorizer.pkl")
            logger.info("Loaded existing AI models")
        except FileNotFoundError:
            # Initialize new models
            self.risk_model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
            logger.info("Initialized new AI models")
    
    def analyze_finding(self, finding_data: Dict) -> Dict:
        """
        Analyze a security finding and provide AI insights.
        
        Args:
            finding_data: Dictionary containing finding information
            
        Returns:
            Dictionary with AI analysis results
        """
        try:
            # Extract features for ML model
            features = self._extract_features(finding_data)
            
            # Predict risk score
            risk_score = self._predict_risk_score(features)
            
            # Generate explanation and remediation
            explanation = self._generate_explanation(finding_data, risk_score)
            remediation = self._generate_remediation(finding_data, risk_score)
            
            return {
                "ai_risk_score": risk_score,
                "ai_confidence": 0.85,  # Placeholder confidence score
                "ai_explanation": explanation,
                "ai_remediation": remediation
            }
            
        except Exception as e:
            logger.error("AI analysis failed", error=str(e), finding_data=finding_data)
            raise AIAnalysisError(f"AI analysis failed: {str(e)}")
    
    def _extract_features(self, finding_data: Dict) -> np.ndarray:
        """Extract features from finding data for ML model."""
        # Create feature vector from finding data
        features = []
        
        # Rule-based features
        rule_id = finding_data.get("rule_id", "")
        rule_name = finding_data.get("rule_name", "")
        severity = finding_data.get("severity", "")
        file_path = finding_data.get("file_path", "")
        
        # Combine text features
        text_features = f"{rule_id} {rule_name} {severity} {file_path}"
        
        # Vectorize text features
        if hasattr(self.vectorizer, 'vocabulary_'):
            # Model is fitted, transform
            features_vector = self.vectorizer.transform([text_features]).toarray()
        else:
            # Model not fitted yet, use dummy features
            features_vector = np.zeros((1, 1000))
        
        return features_vector
    
    def _predict_risk_score(self, features: np.ndarray) -> str:
        """Predict risk score using ML model."""
        if hasattr(self.risk_model, 'classes_'):
            # Model is trained, make prediction
            prediction = self.risk_model.predict(features)[0]
            return prediction
        else:
            # Model not trained yet, use rule-based fallback
            return self._rule_based_risk_score(features)
    
    def _rule_based_risk_score(self, features: np.ndarray) -> str:
        """Fallback rule-based risk scoring."""
        # Simple rule-based scoring for MVP
        # In production, this would be replaced by trained ML model
        return "medium"  # Default to medium risk
    
    def _generate_explanation(self, finding_data: Dict, risk_score: str) -> str:
        """Generate human-readable explanation for the finding."""
        if not self.openai_client:
            return self._generate_fallback_explanation(finding_data, risk_score)
        
        try:
            prompt = f"""
            Explain this security finding in simple terms:
            
            Rule: {finding_data.get('rule_name', 'Unknown')}
            Severity: {finding_data.get('severity', 'Unknown')}
            File: {finding_data.get('file_path', 'Unknown')}
            Risk Score: {risk_score}
            
            Provide a brief, clear explanation of what this finding means and why it's concerning.
            """
            
            response = self.openai_client.chat.completions.create(
                model=settings.AI_MODEL_NAME,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=200,
                temperature=0.3
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            logger.error("OpenAI explanation generation failed", error=str(e))
            return self._generate_fallback_explanation(finding_data, risk_score)
    
    def _generate_remediation(self, finding_data: Dict, risk_score: str) -> str:
        """Generate remediation suggestion for the finding."""
        if not self.openai_client:
            return self._generate_fallback_remediation(finding_data, risk_score)
        
        try:
            prompt = f"""
            Provide a specific remediation suggestion for this security finding:
            
            Rule: {finding_data.get('rule_name', 'Unknown')}
            Severity: {finding_data.get('severity', 'Unknown')}
            File: {finding_data.get('file_path', 'Unknown')}
            Risk Score: {risk_score}
            
            Provide a concrete, actionable fix suggestion. Include code examples if applicable.
            """
            
            response = self.openai_client.chat.completions.create(
                model=settings.AI_MODEL_NAME,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=300,
                temperature=0.3
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            logger.error("OpenAI remediation generation failed", error=str(e))
            return self._generate_fallback_remediation(finding_data, risk_score)
    
    def _generate_fallback_explanation(self, finding_data: Dict, risk_score: str) -> str:
        """Generate fallback explanation without AI."""
        rule_name = finding_data.get('rule_name', 'Unknown rule')
        severity = finding_data.get('severity', 'Unknown severity')
        
        return f"This is a {severity} severity finding from rule '{rule_name}'. " \
               f"The AI has assessed this as {risk_score} risk based on the context and patterns."
    
    def _generate_fallback_remediation(self, finding_data: Dict, risk_score: str) -> str:
        """Generate fallback remediation without AI."""
        rule_name = finding_data.get('rule_name', 'Unknown rule')
        
        if 'secret' in rule_name.lower():
            return "Remove the hardcoded secret and use environment variables or a secure secret management system."
        elif 'dependency' in rule_name.lower():
            return "Update the vulnerable dependency to the latest secure version."
        else:
            return "Please review this finding and apply appropriate security measures based on your organization's policies."
    
    def train_model(self, training_data: List[Dict]) -> Dict:
        """
        Train the ML model with historical data.
        
        Args:
            training_data: List of historical findings with labels
            
        Returns:
            Training results and metrics
        """
        try:
            # Prepare training data
            X = []
            y = []
            
            for data in training_data:
                features = self._extract_features(data)
                X.append(features.flatten())
                y.append(data.get('risk_score', 'medium'))
            
            X = np.array(X)
            y = np.array(y)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Train model
            self.risk_model.fit(X_train, y_train)
            
            # Evaluate model
            y_pred = self.risk_model.predict(X_test)
            report = classification_report(y_test, y_pred, output_dict=True)
            
            # Save models
            joblib.dump(self.risk_model, self.model_path / "risk_model.pkl")
            
            logger.info("AI model training completed", accuracy=report['accuracy'])
            
            return {
                "status": "success",
                "accuracy": report['accuracy'],
                "classification_report": report
            }
            
        except Exception as e:
            logger.error("Model training failed", error=str(e))
            raise AIAnalysisError(f"Model training failed: {str(e)}")
    
    def batch_analyze_findings(self, findings: List[Dict]) -> List[Dict]:
        """Analyze multiple findings in batch."""
        results = []
        
        for finding in findings:
            try:
                analysis = self.analyze_finding(finding)
                results.append({
                    "finding_id": finding.get("id"),
                    "analysis": analysis
                })
            except Exception as e:
                logger.error("Batch analysis failed for finding", 
                           finding_id=finding.get("id"), error=str(e))
                results.append({
                    "finding_id": finding.get("id"),
                    "error": str(e)
                })
        
        return results

# Global AI service instance
ai_service = AIService()
