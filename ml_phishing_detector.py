# ml_phishing_detector.py - Machine Learning Enhanced Phishing Detector
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle
import re
import urllib.parse
from tldextract import extract
import warnings
warnings.filterwarnings('ignore')

class MLPhishingDetector:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.is_trained = False
        
    def extract_features(self, url):
        """Extract comprehensive features from URL for ML analysis"""
        features = {}
        
        # Basic URL features
        features['url_length'] = len(url)
        features['domain_length'] = len(extract(url).domain)
        features['path_length'] = len(urllib.parse.urlparse(url).path)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_at'] = url.count('@')
        features['num_percent'] = url.count('%')
        features['num_equals'] = url.count('=')
        features['num_question'] = url.count('?')
        features['num_ampersand'] = url.count('&')
        
        # Security features
        features['has_https'] = 1 if url.startswith('https://') else 0
        features['has_ip'] = 1 if re.match(r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
        
        # Domain features
        extracted = extract(url)
        features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
        features['has_suspicious_tld'] = 1 if extracted.suffix in ['.tk', '.ml', '.ga', '.cf', '.pw'] else 0
        
        # Keyword features
        suspicious_keywords = ['login', 'secure', 'account', 'update', 'verify', 'banking', 
                              'paypal', 'amazon', 'signin', 'password', 'confirm', 'token']
        url_lower = url.lower()
        features['suspicious_keyword_count'] = sum(1 for keyword in suspicious_keywords if keyword in url_lower)
        
        # Brand impersonation features
        brands = ['google', 'facebook', 'microsoft', 'apple', 'amazon', 'paypal', 'instagram', 'twitter']
        features['brand_mention'] = 1 if any(brand in url_lower for brand in brands) else 0
        features['brand_in_subdomain'] = 1 if extracted.subdomain and any(brand in extracted.subdomain.lower() for brand in brands) else 0
        
        return features
    
    def create_training_data(self):
        """Create synthetic training data for demonstration"""
        # Legitimate URLs
        legitimate_urls = [
            "https://www.google.com",
            "https://www.facebook.com",
            "https://www.microsoft.com",
            "https://www.apple.com",
            "https://www.amazon.com",
            "https://github.com",
            "https://stackoverflow.com",
            "https://www.linkedin.com",
            "https://www.twitter.com",
            "https://www.instagram.com",
            "https://www.youtube.com",
            "https://www.wikipedia.org",
            "https://www.reddit.com",
            "https://medium.com",
            "https://news.ycombinator.com"
        ]
        
        # Phishing URLs (examples)
        phishing_urls = [
            "http://google.secure-login.com",
            "http://facebook-update.com",
            "https://paypal-verify.tk",
            "http://amazon-account-security.ml",
            "https://microsoft-login.ga",
            "http://apple-id-confirm.cf",
            "http://192.168.1.1/login",
            "https://secure-banking-online.com",
            "http://paypal.webscr.com",
            "https://amazon-verify-account.com",
            "http://google.account-update.com",
            "https://facebook-security-check.com",
            "http://microsoft.verification-required.com",
            "https://apple.id.security.com",
            "http://paypal.secure-payment.tk"
        ]
        
        # Extract features
        X_legitimate = [self.extract_features(url) for url in legitimate_urls]
        X_phishing = [self.extract_features(url) for url in phishing_urls]
        
        # Create labels (0 = legitimate, 1 = phishing)
        y_legitimate = [0] * len(legitimate_urls)
        y_phishing = [1] * len(phishing_urls)
        
        # Combine data
        X = X_legitimate + X_phishing
        y = y_legitimate + y_phishing
        
        return X, y, legitimate_urls + phishing_urls
    
    def train_model(self):
        """Train the machine learning model"""
        print("🤖 Training ML Phishing Detector...")
        
        # Create training data
        X, y, urls = self.create_training_data()
        
        # Convert to DataFrame
        df = pd.DataFrame(X)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(df, y, test_size=0.3, random_state=42)
        
        # Train Random Forest model
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"✅ Model trained with accuracy: {accuracy:.2f}")
        print("📊 Classification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        self.is_trained = True
        
        # Save model
        with open('phishing_model.pkl', 'wb') as f:
            pickle.dump(self.model, f)
        
        # Save feature names
        with open('feature_names.pkl', 'wb') as f:
            pickle.dump(df.columns.tolist(), f)
    
    def load_model(self):
        """Load pre-trained model"""
        try:
            with open('phishing_model.pkl', 'rb') as f:
                self.model = pickle.load(f)
            with open('feature_names.pkl', 'rb') as f:
                self.feature_names = pickle.load(f)
            self.is_trained = True
            print("✅ Model loaded successfully")
            return True
        except:
            print("❌ No pre-trained model found. Training new model...")
            return False
    
    def predict_url(self, url):
        """Predict if URL is phishing using ML model"""
        if not self.is_trained:
            if not self.load_model():
                self.train_model()
        
        # Extract features
        features = self.extract_features(url)
        
        # Convert to DataFrame with correct column order
        df = pd.DataFrame([features])
        
        # Ensure columns match training data
        if hasattr(self, 'feature_names'):
            for col in self.feature_names:
                if col not in df.columns:
                    df[col] = 0
            df = df[self.feature_names]
        
        # Make prediction
        prediction = self.model.predict(df)[0]
        probability = self.model.predict_proba(df)[0][1]  # Probability of being phishing
        
        return prediction, probability
    
    def get_feature_importance(self):
        """Get feature importance from trained model"""
        if not self.is_trained:
            return None
        
        feature_names = list(self.extract_features("https://example.com").keys())
        importance = self.model.feature_importances_
        
        return dict(zip(feature_names, importance))

# Test the ML detector
if __name__ == "__main__":
    detector = MLPhishingDetector()
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "http://google.secure-login.com",
        "https://github.com",
        "http://paypal-verify.tk",
        "https://www.facebook.com",
        "http://192.168.1.1/login"
    ]
    
    for url in test_urls:
        prediction, probability = detector.predict_url(url)
        result = "PHISHING" if prediction == 1 else "LEGITIMATE"
        print(f"URL: {url}")
        print(f"Prediction: {result} (Confidence: {probability:.2f})")
        print("-" * 50)
