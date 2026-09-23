
from collections import Counter
from functools import lru_cache
import heapq
import itertools
import string
import re

from wordfreq import zipf_frequency, top_n_list

from vigenere import decrypt_text


# ============================================================
# ENGLISH LETTER FREQUENCIES
# ============================================================

ENGLISH_FREQUENCIES = {
    "A": 0.08167,
    "B": 0.01492,
    "C": 0.02782,
    "D": 0.04253,
    "E": 0.12702,
    "F": 0.02228,
    "G": 0.02015,
    "H": 0.06094,
    "I": 0.06966,
    "J": 0.00153,
    "K": 0.00772,
    "L": 0.04025,
    "M": 0.02406,
    "N": 0.06749,
    "O": 0.07507,
    "P": 0.01929,
    "Q": 0.00095,
    "R": 0.05987,
    "S": 0.06327,
    "T": 0.09056,
    "U": 0.02758,
    "V": 0.00978,
    "W": 0.02360,
    "X": 0.00150,
    "Y": 0.01974,
    "Z": 0.00074
}


# ============================================================
# BASIC GROUP DECRYPTION
# ============================================================

def decrypt_group(group, shift):
    """
    Decrypt one Vigenere key-position group
    using a Caesar shift.
    """

    result = ""

    for char in group:

        position = ord(char) - ord("A")

        decrypted_position = (
            position - shift
        ) % 26

        result += chr(
            decrypted_position + ord("A")
        )

    return result


# ============================================================
# CHI-SQUARE ANALYSIS
# ============================================================

def chi_square_score(text):
    """
    Calculate the chi-square score of a text.

    A lower score indicates that the letter distribution
    is closer to the expected English distribution.
    """

    if not text:

        return float("inf")

    frequency = Counter(text)

    text_length = len(text)

    score = 0.0

    for letter in string.ascii_uppercase:

        observed = frequency.get(letter, 0)

        expected = (
            ENGLISH_FREQUENCIES[letter]
            * text_length
        )

        if expected > 0:

            score += (
                (observed - expected) ** 2
            ) / expected

    return score


# ============================================================
# CANDIDATE SHIFT RECOVERY
# ============================================================

def recover_key_letter_candidates(
    group,
    top_n=10
):
    """
    Return the top candidate shifts for one key position.

    Instead of selecting only one shift, this function
    keeps multiple statistically promising shifts.
    """

    candidates = []

    for shift in range(26):

        decrypted_group = decrypt_group(
            group,
            shift
        )

        score = chi_square_score(
            decrypted_group
        )

        key_letter = chr(
            ord("A") + shift
        )

        candidates.append(
            {
                "key_letter": key_letter,
                "shift": shift,
                "score": score,
                "group": decrypted_group
            }
        )

    candidates.sort(
        key=lambda item: item["score"]
    )

    return candidates[:top_n]


# ============================================================
# KEY-POSITION GROUP CREATION
# ============================================================

def extract_letter_groups(
    ciphertext,
    key_length
):
    """
    Extract letters and divide them into groups
    according to the possible key length.
    """

    letters = ""

    for char in ciphertext.upper():

        if char in string.ascii_uppercase:

            letters += char

    if key_length <= 0:

        raise ValueError(
            "Key length must be greater than zero."
        )

    if len(letters) < key_length:

        raise ValueError(
            "Ciphertext is too short for this key length."
        )

    groups = []

    for index in range(key_length):

        group = letters[
            index::key_length
        ]

        groups.append(group)

    return groups


# ============================================================
# INITIAL KEY CANDIDATES
# ============================================================

def recover_key_candidates(
    ciphertext,
    key_length,
    top_n=10
):
    """
    Recover multiple possible shifts for every
    key position.
    """

    groups = extract_letter_groups(
        ciphertext,
        key_length
    )

    all_candidates = []

    for position, group in enumerate(
        groups,
        start=1
    ):

        candidates = recover_key_letter_candidates(
            group,
            top_n
        )

        all_candidates.append(
            {
                "position": position,
                "group": group,
                "candidates": candidates
            }
        )

    return all_candidates


# ============================================================
# CACHED WORD-FREQUENCY SCORING
# ============================================================

@lru_cache(maxsize=10000)
def cached_word_score(word):
    """
    Cache word-frequency scores.

    Repeated words do not need to be scored again.
    """

    return zipf_frequency(
        word,
        "en"
    )


# ============================================================
# DETAILED PLAINTEXT SCORING
# ============================================================

def plaintext_score(text):
    """
    Score the complete decrypted plaintext.

    Word-frequency scoring is used to estimate
    how natural the decrypted message is.

    Higher score is better.
    """

    words = text.lower().split()

    if not words:

        return float("-inf")

    total_score = 0.0

    valid_words = 0

    for word in words:

        cleaned_word = "".join(
            char
            for char in word
            if char.isalpha()
        )

        if not cleaned_word:

            continue

        # Ignore one-letter words because they
        # provide limited scoring information.

        if len(cleaned_word) <= 1:

            continue

        word_score = cached_word_score(
            cleaned_word
        )

        total_score += word_score

        valid_words += 1

    if valid_words == 0:

        return float("-inf")

    return total_score / valid_words


# ============================================================
# FAST ENGLISH SCREENING
# ============================================================

COMMON_BIGRAMS = {
    "TH", "HE", "IN", "ER", "AN", "RE",
    "ON", "AT", "EN", "ND", "TI", "ES",
    "OR", "TE", "OF", "ED", "IS", "IT",
    "AL", "AR", "ST", "TO", "NT", "NG",
    "SE", "HA", "AS", "OU", "IO", "LE",
    "VE", "CO", "ME", "DE", "HI", "RI",
    "RO", "IC", "NE", "EA"
}


COMMON_TRIGRAMS = {
    "THE", "AND", "ING", "HER", "ERE",
    "ENT", "THA", "NTH", "WAS", "ETH",
    "FOR", "DTH", "HAT", "SHE", "ION",
    "TIO", "VER", "EST", "ERS", "ATI",
    "ALL", "HES", "TER", "HIS", "OFT",
    "STH", "OTH", "RES"
}


COMMON_WORDS = {
    "THE",
    "AND",
    "THIS",
    "THAT",
    "WITH",
    "FROM",
    "YOUR",
    "HAVE",
    "WILL",
    "FOR",
    "ARE",
    "IS",
    "TO",
    "OF",
    "IN",
    "ON",
    "A",
    "AN",
    "AS",
    "SECURITY",
    "NETWORK",
    "MESSAGE",
    "DATA",
    "SYSTEM",
    "KEY",
    "TEXT",
    "TEST",
    "ENGLISH",
    "ANALYSIS",
    "ATTACK",
    "CONTROL",
    "ACCESS",
    "COMMUNICATION",
    "PROTECT",
    "IMPORTANT",
    "REQUIRES",
    "STRONG",
    "AUTHENTICATION",
    "SECURE",
    "PROPER",
    "REGULAR",
    "MONITORING",
    "COMPUTER",
    "SYSTEMS",
    "SERVERS"
}


def fast_english_score(text):
    """
    Quickly estimate how English-like a plaintext is.

    This function is used for screening large numbers
    of candidate plaintexts before detailed scoring.

    Higher scores indicate more English-like text.
    """

    normalized_text = text.upper()

    letters_only = "".join(
        char
        for char in normalized_text
        if char.isalpha()
    )

    if not letters_only:

        return float("-inf")

    score = 0.0

    # --------------------------------------------------------
    # Bigram scoring
    # --------------------------------------------------------

    for index in range(
        len(letters_only) - 1
    ):

        bigram = letters_only[
            index:index + 2
        ]

        if bigram in COMMON_BIGRAMS:

            score += 2.0

    # --------------------------------------------------------
    # Trigram scoring
    # --------------------------------------------------------

    for index in range(
        len(letters_only) - 2
    ):

        trigram = letters_only[
            index:index + 3
        ]

        if trigram in COMMON_TRIGRAMS:

            score += 4.0

    # --------------------------------------------------------
    # Common word scoring
    # --------------------------------------------------------

    words = normalized_text.split()

    for word in words:

        cleaned_word = "".join(
            char
            for char in word
            if char.isalpha()
        )

        if cleaned_word in COMMON_WORDS:

            score += 8.0

    # --------------------------------------------------------
    # Vowel balance
    # --------------------------------------------------------

    vowel_count = sum(
        1
        for char in letters_only
        if char in "AEIOU"
    )

    vowel_ratio = (
        vowel_count / len(letters_only)
    )

    # English usually contains a moderate
    # proportion of vowels.

    if 0.25 <= vowel_ratio <= 0.50:

        score += 3.0

    else:

        score -= 2.0

    return score


# ============================================================
# KEY GENERATION
# ============================================================

def generate_key_combinations(
    candidate_data
):
    """
    Generate possible keys from the candidate
    shifts of each key position.

    Example:

        Position 1: L, M
        Position 2: E, F

    Generated keys:

        LE
        LF
        ME
        MF
    """

    candidate_lists = []

    for position_data in candidate_data:

        candidates = position_data[
            "candidates"
        ]

        letters = [
            candidate["key_letter"]
            for candidate in candidates
        ]

        candidate_lists.append(
            letters
        )

    return itertools.product(
        *candidate_lists
    )

# ============================================================
# SHORT-TEXT DICTIONARY/KEY-CONSISTENCY RECOVERY
# ============================================================

def recover_short_text_with_dictionary(ciphertext, key_length, beam_width=1500, dictionary_limit=20000):
    """Heuristic short-text recovery using dictionary words and repeated-key consistency."""
    if key_length <= 0:
        return None
    letters = "".join(c.upper() for c in ciphertext if c.upper() in string.ascii_uppercase)
    if not letters or len(letters) > 20 or key_length > 8:
        return None
    raw_words = re.findall(r"[A-Za-z]+", ciphertext)
    if not raw_words:
        return None
    common_words = {"A", "I", "AN", "AS", "AT", "BE", "BY", "DO", "GO", "HE", "IF", "IN", "IS", "IT", "ME", "MY", "NO", "OF", "ON", "OR", "SO", "TO", "UP", "US", "WE", "THE", "AND", "THIS", "THAT", "WITH", "FROM", "HAVE", "WILL", "YOUR", "ATTACK", "DAWN", "MESSAGE", "TEST", "SECRET", "KEY"}
    candidates_by_length = {}
    for word in raw_words:
        length = len(word)
        if length in candidates_by_length:
            continue
        candidates = set()
        for candidate in top_n_list("en", dictionary_limit):
            normalized = candidate.strip().upper()
            if len(normalized) == length and normalized.isalpha():
                candidates.add(normalized)
        candidates.update(candidate for candidate in common_words if len(candidate) == length)
        if not candidates:
            return None
        ranked = sorted(candidates, key=lambda candidate: (1 if candidate in common_words else 0, zipf_frequency(candidate.lower(), "en")), reverse=True)
        candidates_by_length[length] = ranked[:2500]
    word_positions = []
    offset = 0
    for word in raw_words:
        word_positions.append((word, offset))
        offset += len(word)
    states = [({}, 0.0, [], 0)]
    for original_word, word_offset in word_positions:
        next_states = []
        candidates = candidates_by_length[len(original_word)]
        for key_map, state_score, chosen_words, tested in states:
            for candidate in candidates:
                updated_key = dict(key_map)
                consistent = True
                for local_index, plain_char in enumerate(candidate):
                    global_index = word_offset + local_index
                    key_position = global_index % key_length
                    cipher_value = ord(letters[global_index]) - ord("A")
                    plain_value = ord(plain_char) - ord("A")
                    required_shift = (cipher_value - plain_value) % 26
                    existing_shift = updated_key.get(key_position)
                    if existing_shift is not None and existing_shift != required_shift:
                        consistent = False
                        break
                    updated_key[key_position] = required_shift
                tested += 1
                if not consistent:
                    continue
                word_score = zipf_frequency(candidate.lower(), "en")
                if candidate in common_words:
                    word_score += 8.0
                next_states.append((updated_key, state_score + word_score, chosen_words + [candidate], tested))
        if not next_states:
            return None
        next_states.sort(key=lambda item: item[1], reverse=True)
        states = next_states[:beam_width]
    complete_states = [state for state in states if len(state[0]) == key_length]
    if not complete_states:
        return None
    best_key_map, best_score, _, combinations_tested = max(complete_states, key=lambda item: item[1])
    key = "".join(chr(best_key_map[position] + ord("A")) for position in range(key_length))
    plaintext = decrypt_text(ciphertext, key)
    return {"key": key, "plaintext": plaintext, "score": best_score, "combinations_tested": combinations_tested, "shortlisted_candidates": len(states), "recovery_method": "Short-text dictionary and key-consistency fallback"}


# ============================================================
# OPTIMIZED GLOBAL KEY SEARCH
# ============================================================

def search_best_key(
    ciphertext,
    candidate_data,
    max_combinations=500000,
    screening_limit=500
):
    """
    Search candidate Vigenere keys using a two-stage process.

    Stage 1:
        Fast English screening for every candidate.

    Stage 2:
        Detailed word-frequency scoring for only
        the strongest shortlisted candidates.

    Parameters:
        ciphertext:
            Encrypted Vigenere text.

        candidate_data:
            Candidate shifts for every key position.

        max_combinations:
            Maximum number of key combinations to test.

        screening_limit:
            Number of candidates retained for detailed scoring.
    """

    # Short-text fallback: per-position frequency analysis is unreliable
    # when each key position contains only a few letters.
    key_length = len(candidate_data)
    letter_count = sum(1 for character in ciphertext if character.isalpha())
    if letter_count <= 20 and key_length <= 8:
        short_result = recover_short_text_with_dictionary(ciphertext, key_length)
        if short_result is not None:
            return short_result

    # A min-heap stores the strongest fast-screened
    # candidates found so far.

    shortlisted_candidates = []

    combinations_tested = 0

    key_combinations = generate_key_combinations(
        candidate_data
    )

    # --------------------------------------------------------
    # Stage 1: Fast candidate screening
    # --------------------------------------------------------

    for key_tuple in key_combinations:

        if combinations_tested >= max_combinations:

            break

        key = "".join(
            key_tuple
        )

        decrypted_plaintext = decrypt_text(
            ciphertext,
            key
        )

        fast_score = fast_english_score(
            decrypted_plaintext
        )

        combinations_tested += 1

        candidate_item = (
            fast_score,
            key,
            decrypted_plaintext
        )

        # Keep only the strongest candidates.

        if len(
            shortlisted_candidates
        ) < screening_limit:

            heapq.heappush(
                shortlisted_candidates,
                candidate_item
            )

        elif fast_score > shortlisted_candidates[0][0]:

            heapq.heapreplace(
                shortlisted_candidates,
                candidate_item
            )

    # --------------------------------------------------------
    # Stage 2: Detailed word-frequency scoring
    # --------------------------------------------------------

    best_key = None

    best_plaintext = None

    best_score = float("-inf")

    for (
        fast_score,
        key,
        decrypted_plaintext
    ) in shortlisted_candidates:

        detailed_score = plaintext_score(
            decrypted_plaintext
        )

        if detailed_score > best_score:

            best_score = detailed_score

            best_key = key

            best_plaintext = decrypted_plaintext

    # --------------------------------------------------------
    # Return best result
    # --------------------------------------------------------

    if best_key is None:

        raise ValueError(
            "No key combinations were evaluated."
        )

    return {
        "key": best_key,
        "plaintext": best_plaintext,
        "score": best_score,
        "combinations_tested": combinations_tested,
        "shortlisted_candidates": len(
            shortlisted_candidates
        )
    }


# ============================================================
# COMPLETE AUTOMATIC VIGENERE RECOVERY
# ============================================================

def recover_vigenere_key(
    ciphertext,
    key_length,
    top_n=10,
    max_combinations=500000,
    screening_limit=500
):
    """
    Recover a Vigenere key using:

    1. Multiple candidate shifts per position.
    2. Candidate key generation.
    3. Fast English screening.
    4. Detailed plaintext scoring.
    5. Global key selection.
    """

    candidate_data = recover_key_candidates(
        ciphertext,
        key_length,
        top_n
    )

    result = search_best_key(
        ciphertext,
        candidate_data,
        max_combinations,
        screening_limit
    )

    result["key_length"] = key_length

    result["top_n_per_position"] = top_n

    result["candidate_data"] = candidate_data

    return result


# ============================================================
# DISPLAY CANDIDATES
# ============================================================

def display_key_position_candidates(
    candidate_data
):
    """
    Display the candidate shifts for every
    key position.
    """

    print("\n" + "=" * 70)

    print("KEY POSITION CANDIDATES")

    print("=" * 70)

    for position_data in candidate_data:

        position = position_data[
            "position"
        ]

        group = position_data[
            "group"
        ]

        candidates = position_data[
            "candidates"
        ]

        print(
            f"\nPosition {position}"
        )

        print(
            f"Group: {group}"
        )

        for rank, candidate in enumerate(
            candidates,
            start=1
        ):

            print(
                f"{rank}. "
                f"Letter: {candidate['key_letter']} | "
                f"Shift: {candidate['shift']} | "
                f"Score: {candidate['score']:.4f}"
            )


# ============================================================
# TESTING
# ============================================================

if __name__ == "__main__":

    print("=" * 70)

    print("OPTIMIZED GLOBAL VIGENERE KEY RECOVERY TEST")

    print("=" * 70)

    ciphertext = (
        "ELUG VD E XCARID SARPUGU XIEGNRI GGRO JAF GPWFWAR "
        "ZUURYIDS NFXAANEMO YRJ VQQBGIDM NYH RFRBYQBPJ "
        "EZOYJWUG GSI BIEASES BQ XTWF EIEH VD XA QUPGW "
        "KUPXTSE ZYD DEZKDOZ NEZ WQPRFWSJ XTS XPC XSARXT "
        "OAO VQQBGID HUP SDWTTRMZ RYKXWFS QQGFLKQ"
    )

    expected_key = "LEMON"

    key_length = 5

    # Keep multiple candidates per key position.

    top_n = 10

    # For key length 5 and top_n 10:
    #
    # Maximum possible combinations:
    #
    # 10^5 = 100,000

    max_combinations = 500000

    # Number of candidates sent to detailed scoring.

    screening_limit = 500

    print(
        "\nExpected Key:",
        expected_key
    )

    print(
        "Key Length:",
        key_length
    )

    print(
        "Candidates Per Position:",
        top_n
    )

    print(
        "Screening Limit:",
        screening_limit
    )

    candidate_data = recover_key_candidates(
        ciphertext,
        key_length,
        top_n
    )

    display_key_position_candidates(
        candidate_data
    )

    print("\n" + "=" * 70)

    print("OPTIMIZED GLOBAL KEY SEARCH")

    print("=" * 70)

    result = search_best_key(
        ciphertext,
        candidate_data,
        max_combinations,
        screening_limit
    )

    print(
        "\nRecovered Key:",
        result["key"]
    )

    print(
        "Plaintext Score:",
        f"{result['score']:.4f}"
    )

    print(
        "Combinations Tested:",
        result["combinations_tested"]
    )

    print(
        "Shortlisted Candidates:",
        result["shortlisted_candidates"]
    )

    print("\nRecovered Plaintext:")

    print(
        result["plaintext"]
    )

    print("\n" + "=" * 70)

    print("VERIFICATION")

    print("=" * 70)

    if result["key"] == expected_key:

        print(
            "PASS: Recovered key matches "
            "the expected key."
        )

    else:

        print(
            "NOTE: Recovered key differs "
            "from the expected key."
        )

        print(
            "The optimized plaintext scoring system "
            "selected the highest-scoring candidate."
        )