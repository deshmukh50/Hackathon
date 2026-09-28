"""
Member 4 - Threat Detection + Statistical Analysis

This module converts quantum measurement results into a
security decision using configurable statistical thresholds.

Independent module:
- No UI
- No AI/ML
- Can be connected to Quantum Engine and Attack Engine
"""

import math
from typing import List, Dict, Any


# ============================================================
# 1. CALCULATE DEVIATION
# ============================================================

def calculate_deviation(expected: float, observed: float) -> float:
    """
    Calculate absolute deviation between expected and observed probability.

    Formula:
        Deviation = |Observed - Expected|

    Parameters:
        expected : Expected probability
        observed : Observed/measured probability

    Returns:
        Absolute deviation
    """

    validate_probability(expected, "expected")
    validate_probability(observed, "observed")

    return abs(observed - expected)


# ============================================================
# 2. CALCULATE FORGERY PROBABILITY
# ============================================================

def calculate_forgery_probability(
    expected: float,
    observed: float,
    threshold: float
) -> float:
    """
    Estimate a simple prototype forgery/attack probability.

    This is a prototype statistical indicator, NOT a
    cryptographically proven QDS forgery probability.

    Logic:
        If deviation <= threshold:
            forgery probability = deviation / threshold

        If deviation > threshold:
            forgery probability = 1.0

    Result is limited to [0, 1].

    Parameters:
        expected  : Expected probability
        observed  : Observed probability
        threshold : Configurable detection threshold

    Returns:
        Prototype forgery probability
    """

    validate_probability(expected, "expected")
    validate_probability(observed, "observed")
    validate_threshold(threshold)

    deviation = calculate_deviation(expected, observed)

    if threshold == 0:
        return 1.0 if deviation > 0 else 0.0

    probability = deviation / threshold

    return min(probability, 1.0)


# ============================================================
# 3. CHECK THRESHOLD
# ============================================================

def check_threshold(deviation: float, threshold: float) -> bool:
    """
    Check whether deviation is within the acceptable threshold.

    Returns:
        True  -> Normal / Accept
        False -> Suspicious / Attack
    """

    if deviation < 0:
        raise ValueError("Deviation cannot be negative.")

    validate_threshold(threshold)

    return deviation <= threshold


# ============================================================
# 4. DETECT ATTACK
# ============================================================

def detect_attack(
    expected: float,
    observed: float,
    threshold: float = 0.15
) -> Dict[str, Any]:
    """
    Detect whether a measurement is normal or suspicious.

    Parameters:
        expected  : Expected probability
        observed  : Observed probability
        threshold : Configurable threshold

    Returns:
        Dictionary containing detection results.
    """

    deviation = calculate_deviation(expected, observed)

    is_normal = check_threshold(deviation, threshold)

    forgery_probability = calculate_forgery_probability(
        expected,
        observed,
        threshold
    )

    if is_normal:
        result = "ACCEPT / NORMAL"
        attack_detected = False
    else:
        result = "SUSPICIOUS / ATTACK"
        attack_detected = True

    return {
        "expected_probability": expected,
        "observed_probability": observed,
        "deviation": deviation,
        "threshold": threshold,
        "forgery_probability": forgery_probability,
        "attack_detected": attack_detected,
        "result": result
    }


# ============================================================
# 5. CALCULATE METRICS
# ============================================================

def calculate_metrics(
    actual_labels: List[str],
    predicted_labels: List[str]
) -> Dict[str, float]:
    """
    Calculate basic threat detection performance metrics.

    Labels:
        NORMAL
        ATTACK

    Parameters:
        actual_labels    : Ground-truth labels
        predicted_labels : Detection engine results

    Returns:
        Dictionary containing:
        - Total tests
        - Normal tests
        - Attack tests
        - Detected attacks
        - Missed attacks
        - False alarms
        - Detection rate
        - False positive rate
    """

    if len(actual_labels) != len(predicted_labels):
        raise ValueError(
            "actual_labels and predicted_labels must have "
            "the same length."
        )

    if len(actual_labels) == 0:
        raise ValueError("At least one test is required.")

    actual = [normalize_label(label) for label in actual_labels]
    predicted = [normalize_label(label) for label in predicted_labels]

    total_tests = len(actual)

    normal_tests = sum(
        1 for label in actual if label == "NORMAL"
    )

    attack_tests = sum(
        1 for label in actual if label == "ATTACK"
    )

    detected_attacks = sum(
        1
        for a, p in zip(actual, predicted)
        if a == "ATTACK" and p == "ATTACK"
    )

    missed_attacks = sum(
        1
        for a, p in zip(actual, predicted)
        if a == "ATTACK" and p == "NORMAL"
    )

    false_alarms = sum(
        1
        for a, p in zip(actual, predicted)
        if a == "NORMAL" and p == "ATTACK"
    )

    true_normals = sum(
        1
        for a, p in zip(actual, predicted)
        if a == "NORMAL" and p == "NORMAL"
    )

    if attack_tests > 0:
        detection_rate = detected_attacks / attack_tests
    else:
        detection_rate = 0.0

    if normal_tests > 0:
        false_positive_rate = false_alarms / normal_tests
    else:
        false_positive_rate = 0.0

    if total_tests > 0:
        accuracy = (
            detected_attacks + true_normals
        ) / total_tests
    else:
        accuracy = 0.0

    return {
        "total_tests": total_tests,
        "normal_tests": normal_tests,
        "attack_tests": attack_tests,
        "detected_attacks": detected_attacks,
        "missed_attacks": missed_attacks,
        "false_alarms": false_alarms,
        "detection_rate": detection_rate,
        "false_positive_rate": false_positive_rate,
        "verification_accuracy": accuracy
    }


# ============================================================
# 6. VALIDATION FUNCTIONS
# ============================================================

def validate_probability(
    value: float,
    name: str = "probability"
) -> None:
    """
    Ensure probability is between 0 and 1.
    """

    if not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number.")

    if math.isnan(value) or math.isinf(value):
        raise ValueError(f"{name} must be a finite number.")

    if not 0.0 <= value <= 1.0:
        raise ValueError(
            f"{name} must be between 0 and 1."
        )


def validate_threshold(threshold: float) -> None:
    """
    Ensure threshold is valid.

    Threshold is configurable for the prototype.
    """

    if not isinstance(threshold, (int, float)):
        raise TypeError("Threshold must be a number.")

    if math.isnan(threshold) or math.isinf(threshold):
        raise ValueError("Threshold must be a finite number.")

    if threshold < 0:
        raise ValueError(
            "Threshold cannot be negative."
        )


def normalize_label(label: str) -> str:
    """
    Convert different label formats into NORMAL or ATTACK.
    """

    if not isinstance(label, str):
        raise TypeError("Labels must be strings.")

    label = label.strip().upper()

    if label in {
        "NORMAL",
        "ACCEPT",
        "ACCEPTED",
        "NORMAL TEST"
    }:
        return "NORMAL"

    if label in {
        "ATTACK",
        "SUSPICIOUS",
        "SUSPICIOUS / ATTACK",
        "ATTACK DETECTED"
    }:
        return "ATTACK"

    raise ValueError(
        f"Unknown label: {label}. "
        "Use NORMAL or ATTACK."
    )


# ============================================================
# 7. FORMAT SINGLE RESULT
# ============================================================

def print_detection_result(result: Dict[str, Any]) -> None:
    """
    Print a detection result in a presentation-friendly format.
    """

    print("\n" + "=" * 50)
    print("       QUANTUM THREAT DETECTION RESULT")
    print("=" * 50)

    print(
        f"Expected Probability : "
        f"{result['expected_probability']:.2f}"
    )

    print(
        f"Observed Probability : "
        f"{result['observed_probability']:.2f}"
    )

    print(
        f"Deviation            : "
        f"{result['deviation']:.2f}"
    )

    print(
        f"Threshold            : "
        f"{result['threshold']:.2f}"
    )

    print(
        f"Forgery Probability  : "
        f"{result['forgery_probability']:.2f}"
    )

    print("-" * 50)

    print(f"RESULT               : {result['result']}")

    print("=" * 50)


# ============================================================
# 8. DEMO
# ============================================================

if __name__ == "__main__":

    # Configurable prototype parameters
    EXPECTED_PROBABILITY = 0.50
    THRESHOLD = 0.15

    # --------------------------------------------------------
    # Example 1: Normal measurement
    # --------------------------------------------------------

    observed_normal = 0.53

    normal_result = detect_attack(
        EXPECTED_PROBABILITY,
        observed_normal,
        THRESHOLD
    )

    print_detection_result(normal_result)

    # --------------------------------------------------------
    # Example 2: Attack measurement
    # --------------------------------------------------------

    observed_attack = 0.72

    attack_result = detect_attack(
        EXPECTED_PROBABILITY,
        observed_attack,
        THRESHOLD
    )

    print_detection_result(attack_result)

    # --------------------------------------------------------
    # Example performance data
    # --------------------------------------------------------

    actual_results = [
        "NORMAL",
        "NORMAL",
        "NORMAL",
        "ATTACK",
        "ATTACK",
        "ATTACK",
        "NORMAL",
        "ATTACK",
        "NORMAL",
        "ATTACK"
    ]

    predicted_results = [
        "NORMAL",
        "NORMAL",
        "ATTACK",
        "ATTACK",
        "ATTACK",
        "NORMAL",
        "NORMAL",
        "ATTACK",
        "NORMAL",
        "ATTACK"
    ]

    metrics = calculate_metrics(
        actual_results,
        predicted_results
    )

    print("\n")
    print("=" * 50)
    print("          DETECTION PERFORMANCE")
    print("=" * 50)

    print(f"Total Tests          : {metrics['total_tests']}")
    print(f"Normal Tests         : {metrics['normal_tests']}")
    print(f"Attack Tests         : {metrics['attack_tests']}")
    print(f"Detected Attacks     : {metrics['detected_attacks']}")
    print(f"Missed Attacks       : {metrics['missed_attacks']}")
    print(f"False Alarms         : {metrics['false_alarms']}")

    print(
        f"Detection Rate       : "
        f"{metrics['detection_rate'] * 100:.2f}%"
    )

    print(
        f"False Positive Rate  : "
        f"{metrics['false_positive_rate'] * 100:.2f}%"
    )

    print(
        f"Verification Accuracy: "
        f"{metrics['verification_accuracy'] * 100:.2f}%"
    )

    print("=" * 50)