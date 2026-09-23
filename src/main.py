
from caesar import (
    encrypt_text as caesar_encrypt_text,
    decrypt_text as caesar_decrypt_text,
    brute_force_caesar,
    automatic_caesar_analysis
)

from vigenere import (
    encrypt_text as vigenere_encrypt_text,
    decrypt_text as vigenere_decrypt_text
)

from vigenere_attack import (
    recover_key_candidates,
    search_best_key,
    fast_english_score
)

from analysis import rank_key_lengths
from security_reporting import AuditLogger, SecurityReport
from datetime import datetime
from pathlib import Path


# ============================================================
# APPLICATION BANNER
# ============================================================

def show_banner():

    print("=" * 55)
    print("       INTERACTIVE CIPHER SECURITY TOOLKIT")
    print("=" * 55)
    print("Caesar and Vigenere Cipher Analysis")
    print("=" * 55)


# ============================================================
# AUTOMATIC CAESAR ANALYSIS DISPLAY
# ============================================================

def display_automatic_analysis(ciphertext):

    """
    Perform automatic Caesar analysis and display
    the result in a user-friendly format.
    """

    result = automatic_caesar_analysis(ciphertext)

    if result["success"]:

        print("\n--- AUTOMATIC CAESAR ANALYSIS ---")

        print(
            "Estimated Shift:",
            result["estimated_shift"]
        )

        print(
            "Recovered Plaintext:",
            result["recovered_text"]
        )

        print(
            "\nNote: Statistical detection may be "
            "inaccurate for short ciphertexts."
        )
        logger = AuditLogger()
        logger.log("Analysis started", "Automatic Caesar shift detection")
        logger.log("Caesar candidates evaluated", "All 26 shifts evaluated")
        logger.log("Detection result generated", f"Estimated shift: {result['estimated_shift']}", "SUCCESS")
        offer_security_report(
            operation="Automatic Caesar Shift Detection",
            cipher_type="CAESAR",
            ciphertext=ciphertext,
            result={"estimated_shift": result["estimated_shift"], "plaintext": result["recovered_text"]},
            findings=["Caesar has a small key space and is vulnerable to brute-force analysis."],
            limitations=["Short or unusual ciphertext may reduce statistical accuracy.", "This is a classical cipher and is not suitable for modern secure communications."],
            audit_logger=logger,
            configuration={"shifts_evaluated": 26}
        )

    else:

        print(
            "\nAnalysis Error:",
            result["message"]
        )


# ============================================================
# SECURITY REPORT GENERATION
# ============================================================

def assess_cipher_strength(cipher_type, operation, ciphertext, result=None, configuration=None):
    """Provide a transparent heuristic assessment, not a cryptographic guarantee."""
    letters = sum(1 for ch in ciphertext if ch.isalpha())
    result = result or {}
    configuration = configuration or {}
    if cipher_type.upper() == "CAESAR":
        strength = "Very Weak"
        assessment = "Caesar has only 26 possible shifts and is vulnerable to brute-force and frequency analysis."
    elif cipher_type.upper() == "VIGENERE":
        key_length = configuration.get("key_length") or result.get("tested_key_length")
        if key_length and int(key_length) <= 3:
            strength = "Weak"
        elif key_length and int(key_length) <= 6:
            strength = "Weak to Moderate"
        else:
            strength = "Context Dependent"
        assessment = "Vigenere is a classical cipher. Repeated keys and sufficient ciphertext can enable statistical attacks; this rating is heuristic."
    else:
        strength = "Uncertain"
        assessment = "The detector provides a statistical estimate; cipher strength cannot be established reliably from this result alone."
    if letters < 50:
        assessment += " The short alphabetic sample reduces confidence in the assessment."
    return strength, assessment


# ============================================================
# PLAINTEXT PLAUSIBILITY EVALUATION
# ============================================================

def evaluate_plaintext_plausibility(plaintext):
    """Conservative heuristic check; does not prove correctness."""
    import re
    letters=[c.lower() for c in plaintext if c.isalpha()]
    count=len(letters)
    if not count:
        return {"status":"Failed English Plausibility Check","confidence":"Very Low","reason":"No alphabetic characters were available.","common_pattern_count":0,"letter_count":0}
    normalized=''.join(letters)
    words=["the","and","that","this","with","from","have","will","your","you","for","not","are","was","is","to","of","in"]
    patterns=["th","he","in","er","an","re","on","at","en","nd","the","and","ing","ion"]
    word_count=sum(1 for w in words if re.search(rf"\b{w}\b",plaintext.lower()))
    pattern_count=sum(1 for pattern in patterns if pattern in normalized)
    vowel_ratio=sum(1 for c in normalized if c in 'aeiou')/count
    base={"common_pattern_count":pattern_count,"letter_count":count}
    if count < 20:
        return {**base,"status":"Unverified Candidate","confidence":"Low","reason":"Fewer than 20 alphabetic characters are available for reliable statistical verification."}
    if vowel_ratio < .15 or vowel_ratio > .60:
        return {**base,"status":"Failed English Plausibility Check","confidence":"Low","reason":"The vowel ratio falls outside a broad heuristic range for ordinary English text."}
    if word_count >= 1 or pattern_count >= 3:
        return {**base,"status":"Plausible Candidate - Manual Verification Required","confidence":"Moderate","reason":"Common English patterns or words were found, but correctness is not proven."}
    return {**base,"status":"Unverified Candidate","confidence":"Low","reason":"Not enough common English patterns or words were found for reliable verification."}

def get_analysis_confidence(letter_count):
    if letter_count < 20:
        return "Low", "Unverified Candidate", "Insufficient Ciphertext Length"
    if letter_count < 40:
        return "Low to Moderate", "Statistical Candidate", "Manual Verification Required"
    if letter_count < 80:
        return "Moderate", "Statistical Candidate", "Manual Verification Required"
    return "Moderate to High", "Statistical Candidate", "Manual Verification Required"


def offer_security_report(
    *,
    operation,
    cipher_type,
    ciphertext,
    result,
    findings,
    limitations,
    audit_logger,
    configuration=None,
    security_assessment=None,
    strength_rating=None
):
    """
    Offer the user an exportable security analysis report.
    Sensitive plaintext and keys are included only when the
    user explicitly chooses to export the report.
    """

    print("\n--- SECURITY REPORT EXPORT ---")
    export_choice = input(
        "Generate an analysis report? (y/n): "
    ).strip().lower()

    if export_choice != "y":
        print("Report export skipped.")
        return

    include_sensitive = input(
        "Include recovered key and plaintext in the report? (y/n): "
    ).strip().lower() == "y"

    report_result = dict(result or {})

    if not include_sensitive:
        report_result.pop("key", None)
        report_result.pop("recovered_key", None)
        report_result.pop("plaintext", None)
        report_result.pop("recovered_plaintext", None)
        report_result["sensitive_output"] = "Excluded by user"

    if strength_rating is None or security_assessment is None:
        strength_rating, security_assessment = assess_cipher_strength(
            cipher_type, operation, ciphertext, report_result, configuration
        )

    report = SecurityReport(
        operation=operation,
        cipher_type=cipher_type,
        ciphertext_length=len(ciphertext),
        letter_count=sum(
            1 for character in ciphertext if character.isalpha()
        ),
        result=report_result,
        findings=findings,
        limitations=limitations,
        audit_events=audit_logger.to_dict(),
        configuration=configuration,
        security_assessment=security_assessment,
        strength_rating=strength_rating
    )

    output_directory = Path("reports")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    try:
        html_path = report.save_html(
            output_directory / f"security_report_{timestamp}.html"
        )
        text_path = report.save_text(
            output_directory / f"security_report_{timestamp}.txt"
        )
        json_path = report.save_json(
            output_directory / f"security_report_{timestamp}.json"
        )
        audit_path = audit_logger.save_json(
            output_directory / f"audit_log_{timestamp}.json"
        )

        print("\nReports generated successfully:")
        print("HTML Report:", html_path)
        print("Text Report:", text_path)
        print("JSON Report:", json_path)
        print("Audit Log:", audit_path)

    except OSError as error:
        print("\nReport export error:", error)


# ============================================================
# VIGENERE AUTOMATIC KEY RECOVERY
# ============================================================


def automatic_vigenere_recovery():
    """
    Recover a Vigenere key and plaintext using
    candidate generation and key combination search.

    The recovery process is statistical and does not
    guarantee the correct key for every ciphertext.
    """

    print("\n--- AUTOMATIC VIGENERE KEY RECOVERY ---")

    ciphertext = input(
        "Enter Vigenere ciphertext: "
    ).strip()

    if not ciphertext:
        print("\nPlease enter a valid ciphertext.")
        return

    key_length_input = input(
        "Enter expected key length: "
    ).strip()

    try:
        key_length = int(key_length_input)

        if key_length <= 0:
            print("\nKey length must be greater than zero.")
            return

    except ValueError:
        print("\nPlease enter a valid integer for the key length.")
        return

    top_n_input = input(
        "Enter candidate count per key position "
        "(recommended: 3, 5, or 10): "
    ).strip()

    try:
        top_n = int(top_n_input)

        if top_n <= 0:
            print("\nCandidate count must be greater than zero.")
            return

    except ValueError:
        print("\nPlease enter a valid integer for the candidate count.")
        return

    # --------------------------------------------------------
    # SEARCH CONFIGURATION
    # --------------------------------------------------------

    total_combinations = top_n ** key_length

    # Safety limit to prevent excessively long searches
    MAX_SEARCH_COMBINATIONS = 3_000_000

    max_combinations = min(
        total_combinations,
        MAX_SEARCH_COMBINATIONS
    )

    SCREENING_LIMIT = 1000

    print("\n--- SEARCH CONFIGURATION ---")
    print(f"Key length: {key_length}")
    print(f"Candidates per position: {top_n}")

    print(
        "Total candidate combinations:",
        f"{total_combinations:,}"
    )

    print(
        "Maximum combinations to test:",
        f"{max_combinations:,}"
    )

    print(
        "Screening limit:",
        f"{SCREENING_LIMIT:,}"
    )

    if total_combinations > MAX_SEARCH_COMBINATIONS:
        print(
            "\nWarning: The complete candidate space exceeds "
            "the configured search limit."
        )

        print(
            f"Only the first {MAX_SEARCH_COMBINATIONS:,} "
            "combinations will be tested."
        )

        print(
            "The correct key may be outside the tested range."
        )

    if max_combinations > 500_000:
        print(
            "\nNotice: This search may take several minutes "
            "depending on your system."
        )

        confirmation = input(
            "\nContinue? (y/n): "
        ).strip().lower()

        if confirmation != "y":
            print("\nSearch cancelled.")
            return

    # --------------------------------------------------------
    # CANDIDATE GENERATION
    # --------------------------------------------------------

    print("\nGenerating key candidates...")

    try:
        candidate_data = recover_key_candidates(
            ciphertext=ciphertext,
            key_length=key_length,
            top_n=top_n
        )

    except Exception as error:
        print(
            "\nError during candidate generation:",
            error
        )
        return

    print("Candidate generation completed.")

    # --------------------------------------------------------
    # KEY COMBINATION SEARCH
    # --------------------------------------------------------

    print("\nStarting automatic key search...")

    try:
        result = search_best_key(
            ciphertext=ciphertext,
            candidate_data=candidate_data,
            max_combinations=max_combinations,
            screening_limit=SCREENING_LIMIT
        )

    except Exception as error:
        print(
            "\nError during key search:",
            error
        )
        return

    if result is None:
        print("\nNo valid result was returned.")
        return

    # --------------------------------------------------------
    # RECOVERY RESULT
    # --------------------------------------------------------

    recovered_key = result["key"]
    recovered_plaintext = result["plaintext"]
    recovered_score = result["score"]
    combinations_tested = result["combinations_tested"]

    shortlisted_candidates = result.get(
        "shortlisted_candidates",
        0
    )

    letter_count = sum(
        1
        for character in ciphertext
        if character.isalpha()
    )

    recovery_plausibility = evaluate_plaintext_plausibility(
        recovered_plaintext
    )

    (
        recovery_confidence,
        recovery_status,
        verification_status
    ) = get_analysis_confidence(letter_count)

    # --------------------------------------------------------
    # RELIABILITY CHECKS
    # --------------------------------------------------------

    # Very short ciphertexts do not contain enough evidence
    # for dependable statistical recovery.

    if letter_count < 20:
        recovery_status = "No Reliable Result"
        verification_status = "Failed - Insufficient Ciphertext"
        recovery_confidence = "Low"

        recovery_plausibility = dict(
            recovery_plausibility
        )

        recovery_plausibility["status"] = verification_status
        recovery_plausibility["confidence"] = recovery_confidence

        recovery_plausibility["reason"] = (
            "Fewer than 20 alphabetic characters are available "
            "for reliable verification."
        )

    elif (
        recovery_plausibility["status"]
        == "Failed English Plausibility Check"
    ):
        recovery_status = "No Reliable Result"
        verification_status = "Failed English Plausibility Check"

        recovery_plausibility = dict(
            recovery_plausibility
        )

        recovery_plausibility["status"] = verification_status

    # --------------------------------------------------------
    # DISPLAY RESULTS
    # --------------------------------------------------------

    print("\n" + "=" * 55)
    print("AUTOMATIC VIGENERE ANALYSIS RESULT")
    print("=" * 55)

    print(
        "\nRecovered Key:",
        recovered_key
    )

    print(
        "\nRecovered Plaintext:",
        recovered_plaintext
    )

    print(
        "\nEnglish Score:",
        f"{recovered_score:.4f}"
    )

    print(
        "Recovery Status:",
        recovery_status
    )

    print(
        "Verification Status:",
        verification_status
    )

    print(
        "Analysis Confidence:",
        recovery_confidence
    )

    print(
        "\nCombinations Tested:",
        f"{combinations_tested:,}"
    )

    print(
        "Shortlisted Candidates:",
        f"{shortlisted_candidates:,}"
    )

    print(
        "\nNote: Automatic recovery is statistical "
        "and may be inaccurate."
    )

    print(
        "Manual verification is required before "
        "accepting the recovered key."
    )

    if total_combinations > max_combinations and combinations_tested >= max_combinations:
        print(
            "\nWarning: The configured search limit was reached."
        )

        print(
            "The correct key may exist outside the tested range."
        )

    # --------------------------------------------------------
    # SECURITY AUDIT LOGGING
    # --------------------------------------------------------

    audit_logger = AuditLogger()

    audit_logger.log(
        "Analysis started",
        "Automatic Vigenere key recovery"
    )

    audit_logger.log(
        "Key search completed",
        f"Combinations tested: {combinations_tested}",
        "SUCCESS"
    )

    if recovery_status == "No Reliable Result":
        audit_logger.log(
            "Recovery verification warning",
            "No reliable key recovery established "
            "from the available ciphertext.",
            "WARNING"
        )

    if total_combinations > max_combinations and combinations_tested >= max_combinations:
        audit_logger.log(
            "Search limit reached",
            "The configured maximum search limit was reached.",
            "WARNING"
        )

    # --------------------------------------------------------
    # SECURITY REPORT
    # --------------------------------------------------------

    offer_security_report(
        operation="Automatic Vigenere Key Recovery",
        cipher_type="Vigenere",
        ciphertext=ciphertext,
        result={
            "key": recovered_key,
            "plaintext": recovered_plaintext,
            "score": recovered_score,
            "combinations_tested": combinations_tested,
            "shortlisted_candidates": shortlisted_candidates,
            "recovery_method": result.get(
                "recovery_method",
                "Statistical candidate search"
            ),
            "recovery_status": recovery_status,
            "verification_status": verification_status,
            "analysis_confidence": recovery_confidence,
            "plaintext_plausibility": recovery_plausibility,
            "letter_count": letter_count,
            "recovery_note": (
                "Candidate displayed for research only; "
                "reliable recovery is not established."
                if recovery_status == "No Reliable Result"
                else
                "Manual verification is required."
            )
        },
        findings=[
            "Vigenere security depends on key length, "
            "key secrecy, and key reuse.",
            "Statistical recovery may be possible "
            "when sufficient ciphertext is available."
        ],
        limitations=[
            "Results are statistical estimates "
            "and require manual verification.",
            "Short or unusual ciphertext may reduce "
            "recovery accuracy.",
            "Large key-search spaces can increase "
            "processing time.",
            "The search limit may prevent the correct "
            "key from being tested."
        ],
        audit_logger=audit_logger,
        configuration={
            "key_length": key_length,
            "candidates_per_position": top_n,
            "total_candidate_combinations": total_combinations,
            "max_combinations": max_combinations,
            "screening_limit": SCREENING_LIMIT
        }
    )


# ============================================================
# VIGENERE KEY-LENGTH ANALYSIS
# ============================================================

def vigenere_key_length_analysis():

    print("\n" + "=" * 55)
    print("VIGENERE KEY-LENGTH ANALYSIS")
    print("=" * 55)

    ciphertext = input(
        "Enter Vigenere ciphertext: "
    ).strip()

    if not ciphertext:
        print("\nPlease enter a valid ciphertext.")
        return

    max_length_input = input(
        "Enter maximum key length (default 10): "
    ).strip()

    if not max_length_input:
        max_key_length = 10
    else:
        try:
            max_key_length = int(max_length_input)

            if max_key_length <= 0:
                print("\nKey length must be greater than zero.")
                return

        except ValueError:
            print("\nPlease enter a valid integer for the maximum key length.")
            return

    letter_count = sum(
        1
        for char in ciphertext
        if char.isalpha()
    )

    if letter_count < 20:
        print("\nWarning: The ciphertext is short.")
        print("IC results may be unreliable.")

    results = rank_key_lengths(
        ciphertext,
        max_key_length
    )

    if not results:
        print("\nUnable to analyze key lengths.")
        return

    print("\nRanked Key-Length Results:")
    print("-" * 55)

    for rank, result in enumerate(results, start=1):
        print(
            f"{rank}. "
            f"Key Length: {result['key_length']} | "
            f"Average IC: {result['average_ic']:.4f}"
        )

    print("\n" + "-" * 55)
    print(
        "Note: Higher IC values may indicate promising key lengths."
    )
    print(
        "IC analysis is statistical and does not guarantee the correct key length."
    )

    audit_logger = AuditLogger()
    audit_logger.log("Key-length analysis started", "Index of Coincidence analysis")
    audit_logger.log(
        "Key-length ranking completed",
        f"Maximum key length tested: {max_key_length}",
        "SUCCESS"
    )
    offer_security_report(
        operation="Vigenere Key-Length Analysis",
        cipher_type="VIGENERE",
        ciphertext=ciphertext,
        result={"ranked_key_lengths": results},
        findings=[
            "Index of Coincidence is a heuristic for identifying promising key lengths.",
            "A promising key length does not prove that the cipher is Vigenere.",
        ],
        limitations=[
            "Short, repetitive, or non-English ciphertext may produce misleading rankings.",
            "Multiples of the actual key length may also receive high scores.",
        ],
        audit_logger=audit_logger,
        configuration={"max_key_length": max_key_length},
    )


# ============================================================
# VIGENERE CIPHER MENU
# ============================================================

def vigenere_menu():

    while True:

        print("\n--- VIGENERE CIPHER MENU ---")

        print("1. Encrypt Text")
        print("2. Decrypt Text")
        print("3. Automatic Key Recovery")
        print("4. Key-Length Analysis")
        print("5. Back to Main Menu")

        choice = input(
            "\nEnter your choice: "
        ).strip()

        # ----------------------------------------------------
        # ENCRYPTION
        # ----------------------------------------------------

        if choice == "1":

            text = input(
                "Enter plaintext: "
            )

            key = input(
                "Enter encryption key: "
            ).strip()

            try:

                encrypted = vigenere_encrypt_text(
                    text,
                    key
                )

                print(
                    "\nEncrypted Text:",
                    encrypted
                )

                audit_logger = AuditLogger()
                audit_logger.log("Encryption started", "Vigenere encryption")
                audit_logger.log("Encryption completed", "Vigenere encryption finished", "SUCCESS")
                offer_security_report(
                    operation="Vigenere Encryption",
                    cipher_type="VIGENERE",
                    ciphertext=encrypted,
                    result={
                        "key": key,
                        "plaintext": text,
                        "encrypted_text": encrypted,
                    },
                    findings=[
                        "Vigenere is a classical cipher and is not modern secure encryption.",
                        "Repeated keys can create patterns that support statistical attacks.",
                    ],
                    limitations=[
                        "This implementation is educational and should not protect sensitive data.",
                    ],
                    audit_logger=audit_logger,
                    configuration={"key_length": len(key)},
                )

            except ValueError as error:

                print(
                    "\nEncryption Error:",
                    error
                )

        # ----------------------------------------------------
        # DECRYPTION
        # ----------------------------------------------------

        elif choice == "2":

            text = input(
                "Enter ciphertext: "
            )

            key = input(
                "Enter decryption key: "
            ).strip()

            try:

                decrypted = vigenere_decrypt_text(
                    text,
                    key
                )

                print(
                    "\nDecrypted Text:",
                    decrypted
                )

                audit_logger = AuditLogger()
                audit_logger.log("Decryption started", "Vigenere decryption")
                audit_logger.log("Decryption completed", "Vigenere decryption finished", "SUCCESS")
                offer_security_report(
                    operation="Vigenere Decryption",
                    cipher_type="VIGENERE",
                    ciphertext=text,
                    result={
                        "key": key,
                        "ciphertext": text,
                        "plaintext": decrypted,
                    },
                    findings=[
                        "Vigenere decryption depends on the secrecy of the key.",
                        "Repeated-key Vigenere can be vulnerable to statistical cryptanalysis.",
                    ],
                    limitations=[
                        "This implementation is educational and should not protect sensitive data.",
                    ],
                    audit_logger=audit_logger,
                    configuration={"key_length": len(key)},
                )

            except ValueError as error:

                print(
                    "\nDecryption Error:",
                    error
                )

        # ----------------------------------------------------
        # AUTOMATIC KEY RECOVERY
        # ----------------------------------------------------

        elif choice == "3":

            automatic_vigenere_recovery()

        # ----------------------------------------------------
        # RETURN TO MAIN MENU
        # ----------------------------------------------------

        elif choice == "4":

            vigenere_key_length_analysis()

        # ----------------------------------------------------
        # RETURN TO MAIN MENU
        # ----------------------------------------------------

        elif choice == "5":

            print(
                "\nReturning to Main Menu..."
            )

            break

        # ----------------------------------------------------
        # INVALID CHOICE
        # ----------------------------------------------------

        else:

            print(
                "\nInvalid choice. "
                "Please select a number from 1 to 5."
            )


# ============================================================
# CAESAR CIPHER MENU
# ============================================================

def caesar_menu():

    while True:

        print("\n--- CAESAR CIPHER MENU ---")

        print("1. Encrypt Text")
        print("2. Decrypt Text")
        print("3. Brute-Force Attack")
        print("4. Automatic Shift Detection")
        print("5. Back to Main Menu")

        choice = input(
            "\nEnter your choice: "
        ).strip()

        # ----------------------------------------------------
        # ENCRYPTION
        # ----------------------------------------------------

        if choice == "1":

            text = input(
                "Enter plaintext: "
            )

            try:

                shift = int(
                    input("Enter shift value: ")
                )

                encrypted = caesar_encrypt_text(
                    text,
                    shift
                )

                print(
                    "\nEncrypted Text:",
                    encrypted
                )

                audit_logger = AuditLogger()
                audit_logger.log("Encryption started", "Caesar encryption")
                audit_logger.log("Encryption completed", f"Shift used: {shift}", "SUCCESS")
                offer_security_report(
                    operation="Caesar Encryption",
                    cipher_type="CAESAR",
                    ciphertext=encrypted,
                    result={
                        "shift": shift,
                        "plaintext": text,
                        "encrypted_text": encrypted,
                    },
                    findings=[
                        "Caesar has only 26 possible shifts and is vulnerable to brute-force analysis.",
                    ],
                    limitations=[
                        "Caesar is a classical cipher and is not suitable for modern secure communications.",
                    ],
                    audit_logger=audit_logger,
                    configuration={"shift": shift},
                )

            except ValueError:

                print(
                    "\nPlease enter a valid number "
                    "for the shift."
                )

        # ----------------------------------------------------
        # DECRYPTION
        # ----------------------------------------------------

        elif choice == "2":

            text = input(
                "Enter ciphertext: "
            )

            try:

                shift = int(
                    input("Enter shift value: ")
                )

                decrypted = caesar_decrypt_text(
                    text,
                    shift
                )

                print(
                    "\nDecrypted Text:",
                    decrypted
                )

                audit_logger = AuditLogger()
                audit_logger.log("Decryption started", "Caesar decryption")
                audit_logger.log("Decryption completed", f"Shift used: {shift}", "SUCCESS")
                offer_security_report(
                    operation="Caesar Decryption",
                    cipher_type="CAESAR",
                    ciphertext=text,
                    result={
                        "shift": shift,
                        "ciphertext": text,
                        "plaintext": decrypted,
                    },
                    findings=[
                        "Caesar is vulnerable to brute-force and frequency analysis.",
                    ],
                    limitations=[
                        "Caesar is a classical cipher and is not suitable for modern secure communications.",
                    ],
                    audit_logger=audit_logger,
                    configuration={"shift": shift},
                )

            except ValueError:

                print(
                    "\nPlease enter a valid number "
                    "for the shift."
                )

        # ----------------------------------------------------
        # BRUTE-FORCE ATTACK
        # ----------------------------------------------------

        elif choice == "3":

            ciphertext = input(
                "Enter ciphertext: "
            )

            if not ciphertext.strip():

                print(
                    "\nPlease enter a valid ciphertext."
                )

            else:

                results = brute_force_caesar(
                    ciphertext
                )

                print(
                    "\n--- CAESAR BRUTE-FORCE RESULTS ---"
                )

                for shift, decrypted_message in results:

                    print(
                        f"Shift {shift}: "
                        f"{decrypted_message}"
                    )

                audit_logger = AuditLogger()
                audit_logger.log("Brute-force attack started", "Caesar: all possible shifts")
                audit_logger.log("Candidates evaluated", "26 Caesar shifts evaluated", "SUCCESS")
                offer_security_report(
                    operation="Caesar Brute-Force Attack",
                    cipher_type="CAESAR",
                    ciphertext=ciphertext,
                    result={
                        "candidate_count": len(results),
                        "candidates": [
                            {"shift": shift, "plaintext": message}
                            for shift, message in results
                        ],
                    },
                    findings=[
                        "Caesar has a very small key space and can be exhaustively searched.",
                        "The analyst must validate candidate plaintext using language and context.",
                    ],
                    limitations=[
                        "The candidate list does not automatically prove which plaintext is correct.",
                    ],
                    audit_logger=audit_logger,
                    configuration={"shifts_evaluated": 26},
                )

        # ----------------------------------------------------
        # AUTOMATIC SHIFT DETECTION
        # ----------------------------------------------------

        elif choice == "4":

            ciphertext = input(
                "Enter ciphertext: "
            )

            display_automatic_analysis(
                ciphertext
            )

        # ----------------------------------------------------
        # RETURN TO MAIN MENU
        # ----------------------------------------------------

        elif choice == "5":

            print(
                "\nReturning to Main Menu..."
            )

            break

        # ----------------------------------------------------
        # INVALID CHOICE
        # ----------------------------------------------------

        else:

            print(
                "\nInvalid choice. "
                "Please select a number from 1 to 5."
            )


# ============================================================
# INTELLIGENT AUTOMATIC CIPHER DETECTION
# ============================================================

def automatic_cipher_detection():

    print("\n" + "=" * 55)
    print("INTELLIGENT AUTOMATIC CIPHER ANALYSIS")
    print("=" * 55)

    ciphertext = input("\nEnter ciphertext: ").strip()

    if not ciphertext:
        print("\nPlease enter a valid ciphertext.")
        return

    letter_count = sum(
        1
        for character in ciphertext
        if character.isalpha()
    )

    if letter_count < 20:
        print("\nWarning: The ciphertext is short.")
        print("Automatic detection may be unreliable.")

    max_length_input = input(
        "Enter maximum Vigenere key length (default 10): "
    ).strip()

    if not max_length_input:
        max_key_length = 10
    else:
        try:
            max_key_length = int(max_length_input)
            if max_key_length <= 0:
                print("\nMaximum key length must be greater than zero.")
                return
        except ValueError:
            print("\nPlease enter a valid integer.")
            return

    print("\n[1/3] Testing Caesar candidates...")

    caesar_result = automatic_caesar_analysis(ciphertext)
    caesar_plaintext = ""
    caesar_shift = None
    caesar_score = float("-inf")

    if caesar_result.get("success"):
        caesar_plaintext = caesar_result.get("recovered_text", "")
        caesar_shift = caesar_result.get("estimated_shift")
        caesar_score = fast_english_score(caesar_plaintext)

    print("[2/3] Ranking possible Vigenere key lengths...")

    key_length_results = rank_key_lengths(
        ciphertext,
        max_key_length
    )

    if not key_length_results:
        print("\nUnable to analyze Vigenere key lengths.")
        return

    top_key_lengths = [
        item["key_length"]
        for item in key_length_results[:3]
    ]

    print("[3/3] Testing promising Vigenere key lengths...")

    best_vigenere_result = None
    best_vigenere_score = float("-inf")
    vigenere_attempts = []

    # Wider candidate coverage with a bounded search.
    candidate_count = 10
    MAX_AUTOMATIC_COMBINATIONS = 3_000_000
    AUTOMATIC_SCREENING_LIMIT = 1000

    for key_length in top_key_lengths:
        total_combinations = candidate_count ** key_length
        search_limit = min(total_combinations, MAX_AUTOMATIC_COMBINATIONS)

        try:
            candidate_data = recover_key_candidates(
                ciphertext=ciphertext,
                key_length=key_length,
                top_n=candidate_count
            )

            result = search_best_key(
                ciphertext=ciphertext,
                candidate_data=candidate_data,
                max_combinations=search_limit,
                screening_limit=AUTOMATIC_SCREENING_LIMIT
            )

            if result is None:
                continue

            plaintext = result.get("plaintext", "")
            comparable_score = fast_english_score(plaintext)
            plausibility = evaluate_plaintext_plausibility(plaintext)

            combinations_tested = result.get("combinations_tested", search_limit)
            search_limit_reached = (
                total_combinations > search_limit
                and combinations_tested >= search_limit
            )

            vigenere_attempts.append({
                "key_length": key_length,
                "key": result.get("key", ""),
                "plaintext": plaintext,
                "score": comparable_score,
                "search_score": result.get("score", 0.0),
                "combinations_tested": combinations_tested,
                "total_combinations": total_combinations,
                "search_limit": search_limit,
                "search_limit_reached": search_limit_reached,
                "plausibility_status": plausibility["status"],
                "confidence": plausibility["confidence"]
            })

            if comparable_score > best_vigenere_score:
                best_vigenere_score = comparable_score
                best_vigenere_result = dict(result)
                best_vigenere_result["comparable_score"] = comparable_score
                best_vigenere_result["tested_key_length"] = key_length
                best_vigenere_result["plausibility"] = plausibility
                best_vigenere_result["total_combinations"] = total_combinations
                best_vigenere_result["search_limit"] = search_limit
                best_vigenere_result["search_limit_reached"] = search_limit_reached

        except Exception as error:
            print(f"\nSkipped Vigenere key length {key_length}: {error}")

    if best_vigenere_result is None and not caesar_result.get("success"):
        print("\nUnable to produce a reliable analysis result.")
        return

    overall_confidence, recovery_status, verification_status = get_analysis_confidence(letter_count)

    if best_vigenere_result is not None and (
        best_vigenere_score > caesar_score
    ):
        detected_type = "VIGENERE"
        recovered_key = best_vigenere_result.get("key", "")
        recovered_plaintext = best_vigenere_result.get("plaintext", "")
        selected_score = best_vigenere_score
        plausibility = best_vigenere_result.get("plausibility", evaluate_plaintext_plausibility(recovered_plaintext))
        verification_status = plausibility["status"]
        reason = [
            "Vigenere analysis produced the strongest English-language score.",
            "The selected result came from a promising key-length candidate.",
            f"Tested key lengths: {', '.join(map(str, top_key_lengths))}.",
            f"Plaintext evaluation: {plausibility['reason']}"
        ]
    else:
        detected_type = "CAESAR"
        recovered_key = (
            f"Shift {caesar_shift}"
            if caesar_shift is not None
            else "Not available"
        )
        recovered_plaintext = caesar_plaintext
        selected_score = caesar_score
        plausibility = evaluate_plaintext_plausibility(recovered_plaintext)
        verification_status = plausibility["status"]
        reason = [
            "Caesar analysis produced the strongest English-language score.",
            "All 26 Caesar shifts were evaluated by the existing analyzer.",
            "Vigenere results were compared against the Caesar candidate.",
            f"Plaintext evaluation: {plausibility['reason']}"
        ]

    print("\n" + "=" * 55)
    print("AUTOMATIC CIPHER DETECTION RESULT")
    print("=" * 55)
    print("\nLikely Cipher Type:", detected_type)
    print("Detection Status: Statistical Estimate")
    print("Recovery Status:", recovery_status)
    print("Verification Status:", verification_status)
    print("Analysis Confidence:", overall_confidence)
    print("Recovered Key / Shift:", recovered_key)
    print("\nRecovered Plaintext:")
    print(recovered_plaintext)
    print("\nComparable English Score:", f"{selected_score:.4f}")

    print("\nReason for Detection:")
    for item in reason:
        print("-", item)

    print("\nVigenere Key-Length Evidence:")
    for rank, item in enumerate(key_length_results[:3], start=1):
        print(
            f"{rank}. Length {item['key_length']} "
            f"(Average IC: {item['average_ic']:.4f})"
        )

    print("\nNote: This is a statistical estimate.")
    print("The recovered plaintext should be manually verified.")
    print("Short, non-English, or unusual ciphertexts may produce")
    print("incorrect classifications or plaintext candidates.")

    audit_logger = AuditLogger()
    audit_logger.log("Analysis started", "Intelligent automatic cipher analysis")
    audit_logger.log(
        "Caesar candidates evaluated",
        "All 26 shifts evaluated"
    )
    audit_logger.log(
        "Vigenere candidates evaluated",
        f"Key lengths considered: {top_key_lengths}"
    )
    audit_logger.log(
        "Detection result generated",
        f"Estimated type: {detected_type}",
        "SUCCESS"
    )

    offer_security_report(
        operation="Intelligent Automatic Cipher Analysis",
        cipher_type=detected_type,
        ciphertext=ciphertext,
        result={
            "detected_type": detected_type,
            "recovered_key_or_shift": recovered_key,
            "plaintext": recovered_plaintext,
            "comparable_english_score": selected_score,
            "tested_vigenere_key_lengths": top_key_lengths,
            "detection_status": "Statistical Estimate",
            "recovery_status": recovery_status,
            "verification_status": verification_status,
            "analysis_confidence": overall_confidence,
            "letter_count": letter_count,
            "plaintext_plausibility": plausibility,
            "vigenere_attempts": vigenere_attempts
        },
        findings=[
            "The result is based on English-language scoring and statistical analysis.",
            "Plaintext plausibility was evaluated using heuristic language patterns.",
            "The recovered plaintext requires manual verification.",
            "Classical ciphers such as Caesar and Vigenere are not suitable for modern secure communications."
        ],
        limitations=[
            "Cipher identification is an estimate and is not guaranteed.",
            "Short, non-English, or unusual ciphertexts may produce incorrect results.",
            "Statistical scoring may select meaningless plaintext candidates.",
            "Plaintext plausibility checks are heuristic and cannot prove correctness.",
            "Recovered plaintext should be manually verified.",
            "A short ciphertext may not contain enough information for reliable key recovery."
        ],
        audit_logger=audit_logger,
        configuration={"max_vigenere_key_length": max_key_length, "tested_key_lengths": top_key_lengths, "caesar_shifts_evaluated": 26},
    )


# ============================================================
# MAIN MENU
# ============================================================

def show_menu():

    print("\n--- MAIN MENU ---")

    print("1. Caesar Cipher")
    print("2. Vigenere Cipher")
    print("3. Automatic Cipher Analysis")
    print("4. Exit")


# ============================================================
# MAIN APPLICATION
# ============================================================

def main():

    show_banner()

    while True:

        show_menu()

        choice = input(
            "\nEnter your choice: "
        ).strip()

        # ----------------------------------------------------
        # CAESAR CIPHER
        # ----------------------------------------------------

        if choice == "1":

            caesar_menu()

        # ----------------------------------------------------
        # VIGENERE CIPHER
        # ----------------------------------------------------

        elif choice == "2":

            vigenere_menu()

        # ----------------------------------------------------
        # AUTOMATIC CIPHER ANALYSIS
        # ----------------------------------------------------

        elif choice == "3":

            automatic_cipher_detection()

        # ----------------------------------------------------
        # EXIT
        # ----------------------------------------------------

        elif choice == "4":

            print(
                "\nThank you for using "
                "Interactive Cipher Security Toolkit."
            )

            print(
                "Exiting program..."
            )

            break

        # ----------------------------------------------------
        # INVALID CHOICE
        # ----------------------------------------------------

        else:

            print(
                "\nInvalid choice. "
                "Please select 1, 2, 3, or 4."
            )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()