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
        # Phishing examples (label 1) - variety of brands/styles
        "Dear customer, your bank account has been locked. Click here to reset your password immediately.",
        "URGENT: Your package delivery failed. Verify your details now at http://bit.ly/fake-track",
        "Congratulations! You won a $1000 Walmart gift card. Claim your reward at this link.",
        "Verify your Netflix billing information now to avoid service interruption.",
        "Suspicious login attempt detected on your account from Russia. Secure it here.",
        "Get rich quick! Work from home and earn $5000 a day. Sign up now!",
        "Hi Mom, I lost my phone. This is my temporary number. Please text me back.",
        "Official security alert from your IT department. Update your credentials immediately.",
        "Your Amazon account password needs to be reset urgently. Confirm billing information now.",
        "Your PayPal account has been limited. Verify your identity within 24 hours.",
        "Apple ID locked due to unusual activity. Sign in here to unlock your account now.",
        "Your Microsoft 365 subscription payment failed. Update payment details immediately or lose access.",
        "Final notice: Your electricity bill is overdue. Pay now to avoid disconnection. Click link.",
        "Your UPI account has been flagged for KYC update. Complete verification within 24 hours.",
        "Winner! You have been selected for a free iPhone 15. Claim now before offer expires.",
        "HDFC Bank: Your debit card will be blocked. Update your details immediately to continue services.",

        # Safe examples (label 0) - variety of everyday contexts
        "Hey, are we still meeting for lunch today at the cafeteria?",
        "The weekly project status report is attached. Please review by Friday afternoon.",
        "Your Amazon order #403-19283 has been shipped. Track your shipment inside.",
        "Can you send over the updated spreadsheet whenever you have a moment?",
        "Reminder: Your dentist appointment is scheduled for tomorrow at 10 AM.",
        "Thanks for the great meeting today, looking forward to next steps.",
        "Your flight booking is confirmed. Check-in opens 24 hours before departure.",
        "Happy birthday! Hope you have a wonderful day.",
        "The team lunch is moved to 1 PM instead of 12 PM, see you there.",
        "Your monthly newsletter subscription has been updated successfully."
    ],
    'label': [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 0,0,0,0,0,0,0,0,0,0]
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