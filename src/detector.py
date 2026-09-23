
from collections import Counter


# -----------------------------------
# English Language Scoring
# -----------------------------------

COMMON_WORDS = [
    "THE", "AND", "THIS", "THAT", "IS",
    "MESSAGE", "SECRET", "HELLO", "YOU",
    "OF", "TO", "IN", "FOR", "WITH"
]


def english_score(text):
    score = 0

    upper_text = text.upper()

    for word in COMMON_WORDS:
        score += upper_text.count(word) * len(word)

    common_patterns = [
        "TH", "HE", "IN", "ER", "AN",
        "RE", "ON", "AT", "EN", "ND"
    ]

    for pattern in common_patterns:
        score += upper_text.count(pattern)

    return score


# -----------------------------------
# Caesar Decryption
# -----------------------------------

def decrypt_caesar(text, shift):
    result = ""

    for char in text:
        if char.isupper():
            position = ord(char) - ord("A")
            decrypted_position = (position - shift) % 26
            result += chr(decrypted_position + ord("A"))

        elif char.islower():
            position = ord(char) - ord("a")
            decrypted_position = (position - shift) % 26
            result += chr(decrypted_position + ord("a"))

        else:
            result += char

    return result


# -----------------------------------
# Caesar Candidate Analysis
# -----------------------------------

def analyze_caesar_candidates(ciphertext):
    candidates = []

    for shift in range(26):
        plaintext = decrypt_caesar(ciphertext, shift)
        score = english_score(plaintext)

        candidates.append({
            "shift": shift,
            "plaintext": plaintext,
            "score": score
        })

    candidates.sort(
        key=lambda candidate: candidate["score"],
        reverse=True
    )

    return candidates


# -----------------------------------
# Index of Coincidence
# -----------------------------------

def calculate_ic(text):
    letters = ""

    for char in text.upper():
        if char.isalpha():
            letters += char

    length = len(letters)

    if length <= 1:
        return 0.0

    frequency = Counter(letters)

    numerator = 0

    for count in frequency.values():
        numerator += count * (count - 1)

    denominator = length * (length - 1)

    return numerator / denominator


# -----------------------------------
# Automatic Detection
# -----------------------------------

def auto_detect(ciphertext):
    print("\n" + "=" * 45)
    print("AUTOMATIC CIPHER DETECTION")
    print("=" * 45)

    if not ciphertext.strip():
        print("Error: Ciphertext cannot be empty.")
        return

    letter_count = sum(
        1 for char in ciphertext if char.isalpha()
    )

    if letter_count < 10:
        print("Warning: Text is short.")
        print("Detection may be unreliable.")

    ic_value = calculate_ic(ciphertext)

    print("\nInput Ciphertext:")
    print(ciphertext)

    print("\nOverall IC:", round(ic_value, 4))

    candidates = analyze_caesar_candidates(ciphertext)

    print("\nTop Caesar Candidates:")

    for candidate in candidates[:5]:
        print(
            f"Shift {candidate['shift']} | "
            f"Score {candidate['score']} | "
            f"{candidate['plaintext']}"
        )

    best_candidate = candidates[0]

    print("\nBest Caesar Candidate:")
    print("Estimated Shift:", best_candidate["shift"])
    print("Estimated Plaintext:", best_candidate["plaintext"])
    print("Language Score:", best_candidate["score"])

    print("\nDetection Note:")
    print(
        "This is a preliminary statistical analysis. "
        "The result is not guaranteed to identify the cipher."
    )


# -----------------------------------
# Test
# -----------------------------------

if __name__ == "__main__":
    test_plaintext = (
        "THIS IS A SECRET MESSAGE "
        "THAT CONTAINS ENOUGH LETTERS FOR ANALYSIS"
    )

    test_ciphertext = decrypt_caesar(test_plaintext, -3)

    auto_detect(test_ciphertext)