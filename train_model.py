import os
import pickle
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline

def train_and_save_model():
    # Synthetic comprehensive dataset for immediate training execution
    data = {
        'text': [
            "Dear customer, your bank account has been locked. Click here to reset your password immediately.",
            "URGENT: Your package delivery failed. Verify your details now at http://bit.ly/fake-track",
            "Congratulations! You won a $1000 Walmart gift card. Claim your reward at this link.",
            "Hey, are we still meeting for lunch today at the cafeteria?",
            "The weekly project status report is attached. Please review by Friday afternoon.",
            "Verify your Netflix billing information now to avoid service interruption.",
            "Your Amazon order #403-19283 has been shipped. Track your shipment inside.",
            "Suspicious login attempt detected on your account from Russia. Secure it here.",
            "Can you send over the updated spreadsheet whenever you have a moment?",
            "Get rich quick! Work from home and earn $5000 a day. Sign up now!",
            "Hi Mom, I lost my phone. This is my temporary number. Please text me back.",
            "Official security alert from your IT department. Update your credentials immediately."
        ],
        'label': [1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1]  # 1 = Phishing, 0 = Safe
    }

    df = pd.DataFrame(data)
    
    # Ensure model target directory exists
    os.makedirs('model', exist_ok=True)
    
    # Vectorizer and Classifier Pipeline
    vectorizer = TfidfVectorizer(stop_words='english', ngram_range=(1, 2))
    X = vectorizer.fit_transform(df['text'])
    y = df['label']
    
    model = MultinomialNB(alpha=0.1)
    model.fit(X, y)
    
    # Save artifacts
    with open('model/vectorizer.pkl', 'wb') as f:
        pickle.dump(vectorizer, f)
    with open('model/phishing_model.pkl', 'wb') as f:
        pickle.dump(model, f)
        
    print("[+] Model and Vectorizer trained and saved successfully inside 'model/' directory.")

if __name__ == '__main__':
    train_and_save_model()