import os
import pickle
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report


def train_and_save_model():
    base_dir = os.path.dirname(__file__)

    # --- Load SMS dataset (UCI SMS Spam Collection) ---
    sms_df = pd.read_csv(os.path.join(base_dir, 'spam.csv'), encoding='latin-1')
    sms_df = sms_df[['v1', 'v2']].rename(columns={'v1': 'label', 'v2': 'text'})
    sms_df['label'] = sms_df['label'].map({'spam': 1, 'ham': 0})

    # --- Load real-world Phishing Email dataset ---
    email_df = pd.read_csv(os.path.join(base_dir, 'phishing_email.csv'))
    email_df = email_df.rename(columns={'text_combined': 'text'})[['text', 'label']]

    # --- Combine both datasets ---
    df = pd.concat([sms_df, email_df], ignore_index=True)
    df.dropna(subset=['text', 'label'], inplace=True)
    df.drop_duplicates(subset=['text'], inplace=True)
    df['label'] = df['label'].astype(int)

    print(f"[+] Combined dataset: {len(df)} samples "
          f"({(df['label'] == 1).sum()} phishing / {(df['label'] == 0).sum()} safe)")
    print(f"    - SMS portion   : {len(sms_df)} samples")
    print(f"    - Email portion : {len(email_df)} samples")

    X_text = df['text'].astype(str)
    y = df['label']

    # --- Train/test split ---
    X_train, X_test, y_train, y_test = train_test_split(
        X_text, y, test_size=0.2, random_state=42, stratify=y
    )

    # --- Vectorizer ---
    vectorizer = TfidfVectorizer(
        stop_words='english',
        ngram_range=(1, 2),
        max_features=8000,
        min_df=2
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # --- Model ---
    model = MultinomialNB(alpha=0.1)
    model.fit(X_train_vec, y_train)

    # --- Evaluate on combined held-out test set ---
    y_pred = model.predict(X_test_vec)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[+] Combined Test Accuracy: {acc * 100:.2f}%")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))

    # --- Retrain on FULL combined dataset before saving ---
    X_full_vec = vectorizer.fit_transform(X_text)
    model.fit(X_full_vec, y)

    # --- Save artifacts ---
    os.makedirs(os.path.join(base_dir, 'model'), exist_ok=True)
    with open(os.path.join(base_dir, 'model', 'vectorizer.pkl'), 'wb') as f:
        pickle.dump(vectorizer, f)
    with open(os.path.join(base_dir, 'model', 'phishing_model.pkl'), 'wb') as f:
        pickle.dump(model, f)

    print("[+] Combined model and vectorizer saved to 'model/' directory.")


if __name__ == '__main__':
    train_and_save_model()
