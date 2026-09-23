
from collections import Counter
import string


# ============================================================
# CAESAR CIPHER ENCRYPTION
# ============================================================

def encrypt_text(text, shift):
    """
    Encrypt text using the Caesar cipher.

    Uppercase and lowercase letters are handled separately.
    Spaces, numbers, and special characters remain unchanged.
    """

    result = ""

    for char in text:
        if char.isupper():
            position = ord(char) - ord("A")
            encrypted_position = (position + shift) % 26
            encrypted_char = chr(encrypted_position + ord("A"))
            result += encrypted_char

        elif char.islower():
            position = ord(char) - ord("a")
            encrypted_position = (position + shift) % 26
            encrypted_char = chr(encrypted_position + ord("a"))
            result += encrypted_char

        else:
            result += char

    return result


# ============================================================
# CAESAR CIPHER DECRYPTION
# ============================================================

def decrypt_text(text, shift):
    """
    Decrypt text using the Caesar cipher.
    """

    return encrypt_text(text, -shift)


# ============================================================
# CAESAR BRUTE-FORCE ANALYSIS
# ============================================================

def brute_force_caesar(ciphertext):
    """
    Try all 26 possible Caesar shifts.

    Returns a list containing the shift and decrypted text
    for each candidate.
    """

    results = []

    for shift in range(26):
        decrypted_message = decrypt_text(ciphertext, shift)
        results.append((shift, decrypted_message))

    return results


# ============================================================
# FREQUENCY ANALYSIS
# ============================================================

def frequency_analysis(text):
    """
    Count the frequency of alphabetic characters in the text.

    Returns a Counter object.
    """

    letters = ""

    for char in text.upper():
        if char in string.ascii_uppercase:
            letters += char

    frequency = Counter(letters)

    return frequency


# ============================================================
# AUTOMATIC CAESAR SHIFT ESTIMATION
# ============================================================

def estimate_caesar_shift(ciphertext):
    """
    Estimate the Caesar shift using English letter frequencies.

    This method is statistical and may be inaccurate for
    short ciphertexts or text that is not English.
    """

    english_frequencies = {
        "A": 8.2, "B": 1.5, "C": 2.8, "D": 4.3,
        "E": 12.7, "F": 2.2, "G": 2.0, "H": 6.1,
        "I": 7.0, "J": 0.15, "K": 0.77, "L": 4.0,
        "M": 2.4, "N": 6.7, "O": 7.5, "P": 1.9,
        "Q": 0.095, "R": 6.0, "S": 6.3, "T": 9.1,
        "U": 2.8, "V": 0.98, "W": 2.4, "X": 0.15,
        "Y": 2.0, "Z": 0.074
    }

    letters = ""

    for char in ciphertext.upper():
        if char in string.ascii_uppercase:
            letters += char

    if len(letters) == 0:
        return None

    best_shift = 0
    lowest_score = float("inf")

    for shift in range(26):
        decrypted_text = decrypt_text(ciphertext, shift)

        decrypted_letters = ""

        for char in decrypted_text.upper():
            if char in string.ascii_uppercase:
                decrypted_letters += char

        counts = Counter(decrypted_letters)
        score = 0
        total = len(decrypted_letters)

        for letter in string.ascii_uppercase:
            observed_count = counts.get(letter, 0)
            expected_count = (
                english_frequencies[letter] / 100
            ) * total

            if expected_count > 0:
                score += (
                    (observed_count - expected_count) ** 2
                ) / expected_count

        if score < lowest_score:
            lowest_score = score
            best_shift = shift

    return best_shift


# ============================================================
# AUTOMATIC CAESAR ANALYSIS
# ============================================================

def automatic_caesar_analysis(ciphertext):
    """
    Estimate the Caesar shift and recover the plaintext.

    Returns a dictionary containing the estimated shift
    and recovered plaintext.
    """

    if not ciphertext or not any(
        char in string.ascii_letters for char in ciphertext
    ):
        return {
            "success": False,
            "message": (
                "Unable to analyze ciphertext. "
                "Please enter text containing alphabetic characters."
            )
        }

    estimated_shift = estimate_caesar_shift(ciphertext)

    if estimated_shift is None:
        return {
            "success": False,
            "message": "Unable to estimate the Caesar shift."
        }

    recovered_text = decrypt_text(ciphertext, estimated_shift)

    return {
        "success": True,
        "estimated_shift": estimated_shift,
        "recovered_text": recovered_text
    }


# ============================================================
# TESTING SECTION
# ============================================================

if __name__ == "__main__":

    print("=" * 55)
    print("CAESAR CIPHER MODULE TESTING")
    print("=" * 55)

    # --------------------------------------------------------
    # Encryption Testing
    # --------------------------------------------------------

    print("\n1. Encryption Testing")

    print("HELLO:", encrypt_text("HELLO", 3))
    print("HELLO WORLD:", encrypt_text("HELLO WORLD", 3))
    print("Hello World!:", encrypt_text("Hello World!", 3))
    print("Hello 123!:", encrypt_text("Hello 123!", 3))

    # --------------------------------------------------------
    # Decryption Testing
    # --------------------------------------------------------

    print("\n2. Decryption Testing")

    encrypted_message = encrypt_text("Hello World!", 3)
    decrypted_message = decrypt_text(encrypted_message, 3)

    print("Encrypted:", encrypted_message)
    print("Decrypted:", decrypted_message)

    # --------------------------------------------------------
    # Brute-Force Testing
    # --------------------------------------------------------

    print("\n3. Brute-Force Testing")

    ciphertext = encrypt_text("HELLO", 3)

    print("Ciphertext:", ciphertext)

    brute_force_results = brute_force_caesar(ciphertext)

    for shift, decrypted_message in brute_force_results:
        print(f"Shift {shift}: {decrypted_message}")

    # --------------------------------------------------------
    # Frequency Analysis Testing
    # --------------------------------------------------------

    print("\n4. Frequency Analysis Testing")

    frequency_result = frequency_analysis("HELLO WORLD")

    for letter, count in frequency_result.most_common():
        print(f"{letter}: {count}")

    # --------------------------------------------------------
    # Automatic Shift Detection Testing
    # --------------------------------------------------------

    print("\n5. Automatic Caesar Shift Detection")

    test_plaintext = (
        "THIS IS A SECRET MESSAGE "
        "THAT CONTAINS ENOUGH LETTERS FOR ANALYSIS"
    )

    test_ciphertext = encrypt_text(test_plaintext, 3)

    
# ============================================================
# IMPROVED CAESAR SHIFT ESTIMATION
# ============================================================

def estimate_caesar_shift(ciphertext):
    """
    Estimate the Caesar shift using English word-frequency
    scoring with a statistical fallback.

    Word-frequency scoring is useful for short English
    messages.
    """

    from wordfreq import zipf_frequency

    if not ciphertext or not any(
        char in string.ascii_letters for char in ciphertext
    ):
        return None

    best_shift = None
    best_score = float("-inf")

    for shift in range(26):

        decrypted_text = decrypt_text(ciphertext, shift)

        words = decrypted_text.lower().split()

        score = 0.0
        valid_words = 0

        for word in words:

            cleaned_word = "".join(
                char for char in word
                if char.isalpha()
            )

            if not cleaned_word:
                continue

            # Ignore very short words during scoring
            if len(cleaned_word) <= 1:
                continue

            word_score = zipf_frequency(
                cleaned_word,
                "en"
            )

            score += word_score
            valid_words += 1

        # Avoid selecting a candidate without usable words
        if valid_words == 0:
            continue

        # Penalize candidates with very uncommon words
        average_score = score / valid_words

        if average_score > best_score:
            best_score = average_score
            best_shift = shift

    return best_shift