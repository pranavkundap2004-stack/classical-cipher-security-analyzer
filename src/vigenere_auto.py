
from analysis import rank_key_lengths
from vigenere_attack import recover_vigenere_key
from vigenere import decrypt_text
from detector import english_score

from wordfreq import zipf_frequency


# ==========================================
# Plaintext Quality Scoring
# ==========================================

def plaintext_score(text):
    """
    Calculate an English plaintext score.

    Combines:
    1. Existing English pattern scoring
    2. Word-frequency scoring

    Higher scores generally indicate more
    English-like plaintext.

    This is a heuristic, not a guarantee.
    """

    score = english_score(text)

    words = text.lower().split()

    word_score = 0.0
    valid_words = 0

    for word in words:

        cleaned_word = "".join(
            char
            for char in word
            if char.isalpha()
        )

        if len(cleaned_word) <= 1:
            continue

        word_score += zipf_frequency(
            cleaned_word,
            "en"
        )

        valid_words += 1

    if valid_words > 0:

        average_word_score = (
            word_score / valid_words
        )

        score += average_word_score * 10

    return score


# ==========================================
# Remove Repeating Key Pattern
# ==========================================

def reduce_repeating_key(key):
    """
    Reduce a key when it contains a complete
    repeating pattern.

    Example:
        LEMONLEMON -> LEMON

    If no repeating pattern exists,
    the original key is returned.
    """

    if not key:
        return key

    for length in range(1, len(key) + 1):

        if len(key) % length != 0:
            continue

        pattern = key[:length]

        repetitions = len(key) // length

        if pattern * repetitions == key:
            return pattern

    return key


# ==========================================
# Key Reduction Details
# ==========================================

def key_reduction_details(key):
    """
    Return information about a recovered key.

    Includes:
    - Original key
    - Reduced key
    - Original length
    - Effective length
    - Reduction status
    """

    reduced_key = reduce_repeating_key(key)

    return {
        "original_key": key,
        "reduced_key": reduced_key,
        "original_length": len(key),
        "effective_length": len(reduced_key),
        "was_reduced": key != reduced_key
    }


# ==========================================
# Build Repeated Key
# ==========================================

def build_repeated_key(key, target_length):
    """
    Repeat a shorter key until the target
    length is reached.

    Example:
        LEMON + target length 10
        -> LEMONLEMON
    """

    if not key or target_length <= 0:
        return ""

    repetitions = target_length // len(key)

    remainder = target_length % len(key)

    return (
        key * repetitions
        + key[:remainder]
    )


# ==========================================
# Compare Repeated Key Pattern
# ==========================================

def compare_repeated_key_pattern(
    shorter_key,
    longer_key
):
    """
    Compare a shorter key with a longer key.

    The shorter key is repeated to the length
    of the longer key.

    Example:
        Shorter key: LEMON
        Longer key:  LEMONYEMON

        Expected:    LEMONLEMON
    """

    if not shorter_key or not longer_key:

        return {
            "is_consistent": False,
            "expected_key": "",
            "mismatch_count": 0
        }

    expected_key = build_repeated_key(
        shorter_key,
        len(longer_key)
    )

    mismatch_count = sum(
        1
        for expected, actual
        in zip(expected_key, longer_key)
        if expected != actual
    )

    return {
        "is_consistent": (
            expected_key == longer_key
        ),
        "expected_key": expected_key,
        "mismatch_count": mismatch_count
    }


# ==========================================
# Candidate Period Validation
# ==========================================

def validate_candidate_periods(candidates):
    """
    Compare longer candidate keys with shorter
    candidate keys when their lengths are
    exact multiples.

    Weak length-1 references are ignored.

    Duplicate reference combinations
    are removed.
    """

    for candidate in candidates:

        candidate["period_checks"] = []

        longer_length = (
            candidate["effective_key_length"]
        )

        longer_key = candidate["expanded_key"]

        checked_references = set()

        for reference in candidates:

            shorter_length = (
                reference["effective_key_length"]
            )

            shorter_key = reference["key"]

            # Ignore length-1 references.
            if shorter_length < 2:
                continue

            # Do not compare a candidate with itself.
            if reference is candidate:
                continue

            # Reference must be shorter.
            if shorter_length >= longer_length:
                continue

            # Length must be an exact multiple.
            if longer_length % shorter_length != 0:
                continue

            reference_identity = (
                shorter_length,
                shorter_key
            )

            if reference_identity in checked_references:
                continue

            checked_references.add(
                reference_identity
            )

            comparison = compare_repeated_key_pattern(
                shorter_key,
                longer_key
            )

            candidate["period_checks"].append({

                "reference_length": (
                    shorter_length
                ),

                "reference_key": (
                    shorter_key
                ),

                "expected_key": (
                    comparison["expected_key"]
                ),

                "is_consistent": (
                    comparison["is_consistent"]
                ),

                "mismatch_count": (
                    comparison["mismatch_count"]
                )

            })

    return candidates


# ==========================================
# Select Strong Reference Candidates
# ==========================================

def get_reference_candidates(candidates):
    """
    Select suitable candidates for repeated-key
    hypothesis correction.

    Length-1 candidates are excluded because
    they are generally weak references.

    Candidates are ranked by plaintext score.
    """

    references = [
        candidate
        for candidate in candidates
        if candidate["effective_key_length"] >= 2
    ]

    references.sort(
        key=lambda candidate: candidate["score"],
        reverse=True
    )

    return references


# ==========================================
# Multiple Candidate Correction
# ==========================================

def correct_multiple_candidates(
    candidates,
    ciphertext
):
    """
    Correct noisy candidate keys when their
    lengths are multiples of shorter candidate
    lengths.

    Example:

        Raw key:
            LEMONYEMON

        Repeated-key hypothesis:
            LEMONLEMON

        Effective key:
            LEMON

    The correction is accepted only when
    the hypothesis produces a higher plaintext
    score than the current candidate.
    """

    reference_candidates = (
        get_reference_candidates(candidates)
    )

    for candidate in candidates:

        candidate["was_corrected"] = False

        candidate["expanded_key"] = (
            candidate["original_key"]
        )

        candidate["correction_reference"] = None

        candidate["raw_recovered_key"] = (
            candidate["original_key"]
        )

        candidate_key_length = (
            candidate["key_length"]
        )

        candidate_key = candidate["key"]

        for reference in reference_candidates:

            if reference is candidate:
                continue

            shorter_length = (
                reference["effective_key_length"]
            )

            shorter_key = reference["key"]

            # The reference must be shorter.
            if shorter_length >= candidate_key_length:
                continue

            # The longer key length must be a
            # multiple of the shorter length.
            if candidate_key_length % shorter_length != 0:
                continue

            # Build the repeated-key hypothesis.
            hypothetical_key = build_repeated_key(
                shorter_key,
                candidate_key_length
            )

            # Skip if no change is needed.
            if hypothetical_key == candidate_key:
                continue

            # Decrypt using the expanded key.
            hypothetical_plaintext = decrypt_text(
                ciphertext,
                hypothetical_key
            )

            hypothetical_score = plaintext_score(
                hypothetical_plaintext
            )

            # Accept only if the hypothesis has
            # a better score.
            if hypothetical_score > candidate["score"]:

                candidate["raw_recovered_key"] = (
                    candidate["original_key"]
                )

                candidate["expanded_key"] = (
                    hypothetical_key
                )

                candidate["plaintext"] = (
                    hypothetical_plaintext
                )

                candidate["score"] = (
                    hypothetical_score
                )

                candidate["was_corrected"] = True

                candidate["correction_reference"] = {
                    "key_length": shorter_length,
                    "key": shorter_key
                }

                # Calculate effective key details.
                key_details = key_reduction_details(
                    hypothetical_key
                )

                candidate["key"] = (
                    key_details["reduced_key"]
                )

                candidate["effective_key_length"] = (
                    key_details["effective_length"]
                )

                candidate["was_reduced"] = (
                    key_details["was_reduced"]
                )

                # Stop after the strongest suitable
                # reference has produced a correction.
                break

    return candidates


# ==========================================
# Automatic Vigenère Analysis
# ==========================================

def automatic_vigenere_analysis(
    ciphertext,
    max_key_length=10,
    number_of_candidates=5
):
    """
    Automatically estimate the Vigenère key
    and recover the plaintext.

    Workflow:

    1. Validate ciphertext.
    2. Rank key lengths using IC.
    3. Recover a key for each selected length.
    4. Reduce exact repeating patterns.
    5. Decrypt the ciphertext.
    6. Score the plaintext.
    7. Correct noisy multiple-length candidates.
    8. Validate repeating-key consistency.
    9. Sort candidates by plaintext score.
    10. Return the best candidate.

    Results are statistical estimates and
    should be validated with further testing.
    """

    # --------------------------------------
    # Input Validation
    # --------------------------------------

    if not ciphertext.strip():

        return {
            "success": False,
            "message": "Ciphertext cannot be empty."
        }

    letter_count = sum(
        1
        for char in ciphertext
        if char.isalpha()
    )

    if letter_count < 30:

        return {
            "success": False,
            "message": (
                "Ciphertext is too short for "
                "reliable automatic analysis."
            )
        }

    # --------------------------------------
    # Key-Length Ranking
    # --------------------------------------

    ranked_lengths = rank_key_lengths(
        ciphertext,
        max_key_length
    )

    if not ranked_lengths:

        return {
            "success": False,
            "message": "Unable to estimate key lengths."
        }

    candidates = []

    selected_lengths = ranked_lengths[
        :number_of_candidates
    ]

    # --------------------------------------
    # Candidate Key Recovery
    # --------------------------------------

    for length_result in selected_lengths:

        key_length = length_result["key_length"]

        try:

            key_result = recover_vigenere_key(
                ciphertext,
                key_length
            )

            recovered_key = key_result["key"]

            key_details = key_reduction_details(
                recovered_key
            )

            reduced_key = (
                key_details["reduced_key"]
            )

            recovered_plaintext = decrypt_text(
                ciphertext,
                reduced_key
            )

            score = plaintext_score(
                recovered_plaintext
            )

            candidates.append({

                # Estimated length from IC.
                "key_length": key_length,

                # Details about the raw key.
                "original_key_length": (
                    key_details["original_length"]
                ),

                "effective_key_length": (
                    key_details["effective_length"]
                ),

                # IC value for this candidate.
                "ic": length_result["average_ic"],

                # Raw recovered key.
                "original_key": (
                    key_details["original_key"]
                ),

                "raw_recovered_key": (
                    key_details["original_key"]
                ),

                # Reduced key used for decryption.
                "key": reduced_key,

                # Expanded key before correction.
                "expanded_key": recovered_key,

                # Key status.
                "was_reduced": (
                    key_details["was_reduced"]
                ),

                "was_corrected": False,

                "correction_reference": None,

                # Decryption result.
                "plaintext": recovered_plaintext,

                # Plaintext quality score.
                "score": score

            })

        except (ValueError, KeyError):

            continue

    if not candidates:

        return {
            "success": False,
            "message": (
                "Unable to recover a candidate key."
            )
        }

    # --------------------------------------
    # Correct Multiple-Length Candidates
    # --------------------------------------

    candidates = correct_multiple_candidates(
        candidates,
        ciphertext
    )

    # --------------------------------------
    # Validate Key Periods
    # --------------------------------------

    candidates = validate_candidate_periods(
        candidates
    )

    # --------------------------------------
    # Rank Candidates
    # --------------------------------------

    candidates.sort(
        key=lambda candidate: candidate["score"],
        reverse=True
    )

    best_candidate = candidates[0]

    return {
        "success": True,
        "best_candidate": best_candidate,
        "all_candidates": candidates
    }


# ==========================================
# Testing
# ==========================================

if __name__ == "__main__":

    print("=" * 60)
    print("AUTOMATIC VIGENERE ANALYSIS TEST")
    print("=" * 60)

    ciphertext = (
        "ELUG VD E XCARID SARPUGU XIEGNRI GGRO JAF "
        "GPWFWAR ZUURYIDS NFXAANEMO YRJ VQQBGIDM "
        "NYH RFRBYQBPJ EZOYJWUG GSI BIEASES BQ "
        "XTWF EIEH VD XA QUPGW KUPXTSE ZYD "
        "DEZKDOZ NEZ WQPRFWSJ XTS XPC XSARXT "
        "OAO VQQBGID HUP SDWTTRMZ RYKXWFS QQGFLKQ"
    )

    expected_key = "LEMON"

    result = automatic_vigenere_analysis(
        ciphertext,
        max_key_length=10,
        number_of_candidates=5
    )

    if not result["success"]:

        print("\nAnalysis Failed:")
        print(result["message"])

    else:

        best_candidate = result["best_candidate"]

        print("\nExpected Key:", expected_key)

        print(
            "\nEstimated Key Length:",
            best_candidate["key_length"]
        )

        print(
            "Recovered Key:",
            best_candidate["key"]
        )

        print(
            "IC Value:",
            round(best_candidate["ic"], 4)
        )

        print(
            "Plaintext Score:",
            round(best_candidate["score"], 4)
        )

        print("\nRecovered Plaintext:")
        print(best_candidate["plaintext"])

        print("\nCandidate Summary:")

        for candidate in result["all_candidates"]:

            reduction_status = (
                "Reduced"
                if candidate["was_reduced"]
                else "Not reduced"
            )

            corrected_status = (
                " | Corrected via Hypothesis"
                if candidate.get("was_corrected")
                else ""
            )

            print(
                "\nEstimated Length: "
                f"{candidate['key_length']} | "

                "Effective Length: "
                f"{candidate['effective_key_length']} | "

                "Raw Recovered Key: "
                f"{candidate['raw_recovered_key']} | "

                "Expanded Key: "
                f"{candidate['expanded_key']} | "

                "Effective Key: "
                f"{candidate['key']} | "

                "Score: "
                f"{candidate['score']:.4f} | "

                f"{reduction_status}"
                f"{corrected_status}"
            )

            if candidate.get(
                "correction_reference"
            ):

                reference = (
                    candidate["correction_reference"]
                )

                print(
                    "   Correction Reference: "
                    f"Length {reference['key_length']} "
                    f"({reference['key']})"
                )

            for check in candidate.get(
                "period_checks",
                []
            ):

                consistency_status = (
                    "Consistent"
                    if check["is_consistent"]
                    else "Inconsistent"
                )

                print(
                    "   Compared with Length "
                    f"{check['reference_length']} "
                    f"({check['reference_key']}) | "

                    "Expected: "
                    f"{check['expected_key']} | "

                    "Mismatches: "
                    f"{check['mismatch_count']} | "

                    f"{consistency_status}"
                )

        print("\nVerification:")

        if best_candidate["key"] == expected_key:

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
                "The analyzer is statistical and "
                "requires further testing."
            )