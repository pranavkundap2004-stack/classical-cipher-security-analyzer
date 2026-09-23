
from collections import Counter, defaultdict


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

    ic = numerator / denominator

    return ic


def average_ic_for_key_length(ciphertext, key_length):
    letters = ""

    for char in ciphertext.upper():
        if char.isalpha():
            letters += char

    if key_length <= 0:
        return 0.0

    groups = []

    for index in range(key_length):
        group = letters[index::key_length]
        groups.append(group)

    ic_values = []

    for group in groups:
        if len(group) > 1:
            ic_values.append(calculate_ic(group))

    if len(ic_values) == 0:
        return 0.0

    return sum(ic_values) / len(ic_values)


def analyze_key_lengths(ciphertext, max_key_length=10):
    print("\nVigenere Key-Length Analysis")

    for key_length in range(1, max_key_length + 1):
        average_ic = average_ic_for_key_length(
            ciphertext,
            key_length
        )

        print(
            f"Key Length {key_length}: "
            f"Average IC = {average_ic:.4f}"
        )


def rank_key_lengths(ciphertext, max_key_length=10):
    """
    Rank possible Vigenere key lengths using
    average Index of Coincidence (IC).

    Higher IC values can indicate a more
    promising key length.

    Returns a list of dictionaries sorted
    by average IC in descending order.
    """

    letters = ""

    for char in ciphertext.upper():
        if char.isalpha():
            letters += char

    if len(letters) < 2:
        return []

    results = []

    for key_length in range(1, max_key_length + 1):

        if key_length > len(letters):
            break

        average_ic = average_ic_for_key_length(
            letters,
            key_length
        )

        results.append({
            "key_length": key_length,
            "average_ic": average_ic
        })

    results.sort(
        key=lambda result: result["average_ic"],
        reverse=True
    )

    return results


def kasiski_examination(ciphertext, sequence_length=3):
    letters = ""

    for char in ciphertext.upper():
        if char.isalpha():
            letters += char

    sequences = defaultdict(list)

    for index in range(len(letters) - sequence_length + 1):
        sequence = letters[
            index:index + sequence_length
        ]

        sequences[sequence].append(index)

    distances = []
    factor_counts = Counter()

    for sequence, positions in sequences.items():

        if len(positions) > 1:

            for i in range(len(positions)):

                for j in range(i + 1, len(positions)):

                    distance = positions[j] - positions[i]

                    distances.append(
                        (sequence, distance)
                    )

                    for factor in range(
                        2,
                        min(distance, 20) + 1
                    ):

                        if distance % factor == 0:
                            factor_counts[factor] += 1

    print("\nKasiski Examination")

    if not distances:
        print("No repeated sequences found.")
        return []

    print("Repeated Sequence Distances:")

    for sequence, distance in distances:
        print(
            f"{sequence}: Distance = {distance}"
        )

    print("\nCandidate Key Lengths:")

    for factor, count in factor_counts.most_common():
        print(
            f"Length {factor}: "
            f"{count} occurrence(s)"
        )

    return factor_counts


if __name__ == "__main__":

    print("Index of Coincidence Test")

    test_text = (
        "THIS IS A SAMPLE ENGLISH TEXT "
        "FOR TESTING FREQUENCY PATTERNS"
    )

    ic_value = calculate_ic(test_text)

    print("Text:", test_text)
    print("IC Value:", round(ic_value, 4))

    print("\nKey-Length Analysis Test")

    sample_ciphertext = (
        "LXFOPVEFRNHRLXFOPVEFRNHR"
        "LXFOPVEFRNHRLXFOPVEFRNHR"
    )

    analyze_key_lengths(
        sample_ciphertext,
        10
    )

    print("\nKasiski Test")

    kasiski_examination(
        "ABCXYZABCDEFABCXYZABCDEF",
        sequence_length=3
    )

    print("\nRanked Key-Length Analysis Test")

    ranked_results = rank_key_lengths(
        sample_ciphertext,
        max_key_length=10
    )

    for result in ranked_results:

        print(
            f"Key Length: {result['key_length']} | "
            f"Average IC: {result['average_ic']:.4f}"
        )

    print("\n" + "=" * 60)
    print("REALISTIC VIGENERE KEY-LENGTH ANALYSIS TEST")
    print("=" * 60)

    realistic_ciphertext = (
        "ELUG VD E XCARID SARPUGU XIEGNRI GGRO JAF GPWFWAR "
        "ZUURYIDS NFXAANEMO YRJ VQQBGIDM NYH RFRBYQBPJ "
        "EZOYJWUG GSI BIEASES BQ XTWF EIEH VD XA QUPGW "
        "KUPXTSE ZYD DEZKDOZ NEZ WQPRFWSJ XTS XPC XSARXT "
        "OAO VQQBGID HUP SDWTTRMZ RYKXWFS QQGFLKQ"
    )

    print("\nExpected Key: LEMON")
    print("Expected Key Length: 5")

    ranked_results = rank_key_lengths(
        realistic_ciphertext,
        max_key_length=10
    )

    print("\nRanked Key-Length Results:")

    for result in ranked_results:

        print(
            f"Key Length: {result['key_length']} | "
            f"Average IC: {result['average_ic']:.4f}"
        )