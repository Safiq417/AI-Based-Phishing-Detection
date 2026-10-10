import os
import pickle
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline

def train_and_save_model():
    print("[*] Downloading and loading the SMS Spam Collection Dataset...")
    url = "https://raw.githubusercontent.com/mohitgupta-1O1/Kaggle-SMS-Spam-Collection-Dataset-/master/spam.csv"
    
    try:
        # Load the classic SMS Spam Collection dataset
        df = pd.read_csv(url, encoding='latin-1')
        # Kaggle CSV has extra empty columns, we only need v1 (label) and v2 (text)
        df = df[['v1', 'v2']].copy()
        df.columns = ['label', 'text']
        # Map labels to binary: 0 for ham (safe), 1 for spam (phishing)
        df['label'] = df['label'].map({'ham': 0, 'spam': 1})
        
        # Drop any NaN values that might have crept in
        df = df.dropna()
        print(f"[+] Successfully loaded {len(df)} samples from the dataset.")
    except Exception as e:
        print(f"[-] Error loading dataset: {e}")
        print("[!] Make sure you have an active internet connection.")
        return
    
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