
import string


# ============================================================
# KEY VALIDATION
# ============================================================

def validate_key(key):
    """
    Validate the Vigenère cipher key.

    The key must contain alphabetic characters only
    and cannot be empty.
    """

    if not key:
        return False

    return all(char in string.ascii_letters for char in key)


# ============================================================
# VIGENERE ENCRYPTION
# ============================================================

def encrypt_text(text, key):
    """
    Encrypt text using the Vigenère cipher.

    Uppercase and lowercase letters are preserved.
    Spaces, numbers, and special characters remain unchanged.
    The key repeats throughout the message.
    """

    if not validate_key(key):
        raise ValueError(
            "Invalid key. Please use alphabetic characters only."
        )

    result = ""
    key = key.upper()
    key_index = 0

    for char in text:

        if char.isupper():
            plaintext_position = ord(char) - ord("A")
            key_shift = ord(key[key_index % len(key)]) - ord("A")

            encrypted_position = (
                plaintext_position + key_shift
            ) % 26

            result += chr(encrypted_position + ord("A"))
            key_index += 1

        elif char.islower():
            plaintext_position = ord(char) - ord("a")
            key_shift = ord(key[key_index % len(key)]) - ord("A")

            encrypted_position = (
                plaintext_position + key_shift
            ) % 26

            result += chr(encrypted_position + ord("a"))
            key_index += 1

        else:
            result += char

    return result


# ============================================================
# VIGENERE DECRYPTION
# ============================================================

def decrypt_text(text, key):
    """
    Decrypt text using the Vigenère cipher.

    The same key used during encryption is required.
    """

    if not validate_key(key):
        raise ValueError(
            "Invalid key. Please use alphabetic characters only."
        )

    result = ""
    key = key.upper()
    key_index = 0

    for char in text:

        if char.isupper():
            ciphertext_position = ord(char) - ord("A")
            key_shift = ord(key[key_index % len(key)]) - ord("A")

            decrypted_position = (
                ciphertext_position - key_shift
            ) % 26

            result += chr(decrypted_position + ord("A"))
            key_index += 1

        elif char.islower():
            ciphertext_position = ord(char) - ord("a")
            key_shift = ord(key[key_index % len(key)]) - ord("A")

            decrypted_position = (
                ciphertext_position - key_shift
            ) % 26

            result += chr(decrypted_position + ord("a"))
            key_index += 1

        else:
            result += char

    return result


# ============================================================
# TESTING SECTION
# ============================================================

if __name__ == "__main__":

    print("=" * 55)
    print("VIGENERE CIPHER MODULE TESTING")
    print("=" * 55)

    plaintext = "ATTACK AT DAWN"
    key = "LEMON"

    # --------------------------------------------------------
    # Encryption Testing
    # --------------------------------------------------------

    print("\n1. Encryption Testing")

    encrypted_text = encrypt_text(plaintext, key)

    print("Plaintext:", plaintext)
    print("Key:", key)
    print("Encrypted Text:", encrypted_text)

    # --------------------------------------------------------
    # Decryption Testing
    # --------------------------------------------------------

    print("\n2. Decryption Testing")

    decrypted_text = decrypt_text(encrypted_text, key)

    print("Ciphertext:", encrypted_text)
    print("Key:", key)
    print("Decrypted Text:", decrypted_text)

    # --------------------------------------------------------
    # Additional Tests
    # --------------------------------------------------------

    print("\n3. Additional Testing")

    test_cases = [
        ("HELLO WORLD", "KEY"),
        ("Hello World!", "DOG"),
        ("Python 123!", "CODE"),
        ("Attack at Dawn", "LEMON"),
    ]

    for test_plaintext, test_key in test_cases:

        test_ciphertext = encrypt_text(
            test_plaintext,
            test_key
        )

        recovered_text = decrypt_text(
            test_ciphertext,
            test_key
        )

        print("\nPlaintext:", test_plaintext)
        print("Key:", test_key)
        print("Encrypted:", test_ciphertext)
        print("Decrypted:", recovered_text)

        if recovered_text == test_plaintext:
            print("Status: PASS")
        else:
            print("Status: FAIL")

    # --------------------------------------------------------
    # Invalid Key Testing
    # --------------------------------------------------------

    print("\n4. Invalid Key Testing")

    invalid_keys = ["", "123", "KEY123", "!@#"]

    for invalid_key in invalid_keys:

        try:
            encrypt_text("HELLO", invalid_key)
            print(
                f"Key '{invalid_key}': FAIL - "
                "Invalid key was accepted."
            )

        except ValueError as error:
            print(
                f"Key '{invalid_key}': PASS - {error}"
            )

    print("\nTesting completed.")

    
if __name__ == "__main__":

    print("=" * 60)
    print("VIGENERE REALISTIC TEST")
    print("=" * 60)

    plaintext = (
        "THIS IS A LONGER ENGLISH MESSAGE USED FOR TESTING "
        "VIGENERE AUTOMATIC KEY RECOVERY AND FREQUENCY ANALYSIS "
        "THE PURPOSE OF THIS TEST IS TO CHECK WHETHER OUR "
        "PROGRAM CAN IDENTIFY THE KEY LENGTH AND RECOVER "
        "THE ORIGINAL ENGLISH MESSAGE"
    )

    key = "LEMON"

    ciphertext = encrypt_text(plaintext, key)

    print("\nOriginal Plaintext:")
    print(plaintext)

    print("\nEncryption Key:")
    print(key)

    print("\nGenerated Ciphertext:")
    print(ciphertext)

    recovered_text = decrypt_text(ciphertext, key)

    print("\nDecrypted Text:")
    print(recovered_text)

    print("\nVerification:")

    if recovered_text == plaintext:
        print("PASS: Decryption matches the original plaintext.")
    else:
        print("FAIL: Decryption does not match the original plaintext.")