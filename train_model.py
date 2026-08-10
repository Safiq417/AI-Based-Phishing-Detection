import os
import pickle
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report


def train_and_save_model():
    # --- Load real-world dataset (UCI SMS Spam Collection) ---
    csv_path = os.path.join(os.path.dirname(__file__), 'spam.csv')
    df = pd.read_csv(csv_path, encoding='latin-1')

    # Keep only the relevant columns and rename them
    df = df[['v1', 'v2']].rename(columns={'v1': 'label', 'v2': 'text'})

    # Convert labels: spam -> 1 (phishing/malicious), ham -> 0 (safe)
    df['label'] = df['label'].map({'spam': 1, 'ham': 0})

    # Basic cleanup
    df.dropna(subset=['text', 'label'], inplace=True)
    df.drop_duplicates(subset=['text'], inplace=True)

    print(f"[+] Loaded {len(df)} messages "
          f"({(df['label'] == 1).sum()} spam / {(df['label'] == 0).sum()} ham)")

    X_text = df['text']
    y = df['label']

    # --- Train/test split so we can measure real accuracy ---
    X_train, X_test, y_train, y_test = train_test_split(
        X_text, y, test_size=0.2, random_state=42, stratify=y
    )

    # --- Vectorizer ---
    vectorizer = TfidfVectorizer(
        stop_words='english',
        ngram_range=(1, 2),
        max_features=5000,
        min_df=2
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # --- Model ---
    model = MultinomialNB(alpha=0.1)
    model.fit(X_train_vec, y_train)

    # --- Evaluate ---
    y_pred = model.predict(X_test_vec)
    acc = accuracy_score(y_test, y_pred)
    print(f"[+] Test Accuracy: {acc * 100:.2f}%")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))

    # --- Retrain on FULL dataset before saving (use all available data) ---
    X_full_vec = vectorizer.fit_transform(X_text)
    model.fit(X_full_vec, y)

    # --- Save artifacts ---
    os.makedirs('model', exist_ok=True)
    with open('model/vectorizer.pkl', 'wb') as f:
        pickle.dump(vectorizer, f)
    with open('model/phishing_model.pkl', 'wb') as f:
        pickle.dump(model, f)

    print("[+] Model and Vectorizer trained and saved successfully inside 'model/' directory.")


if __name__ == '__main__':
    train_and_save_model()
