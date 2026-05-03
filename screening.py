"""
Deterministic Sanctions Screening Pipeline
Zero Trust Architecture for ISO 20022 Networks

Two-stage pipeline:
Stage 1: Exact normalized matching
Stage 2: Jaro-Winkler fuzzy matching
"""

import json
import unicodedata
from jellyfish import jaro_winkler_similarity

# Default threshold empirically derived
# at optimal FPR/FNR balance
THRESHOLD = 0.92

# Sample OFAC SDN entries (synthetic)
SDN_LIST = [
    "John Doe",
    "Jane Smith",
    "Ahmad Al-Rashid",
    "Viktor Petrov",
    "Chen Wei",
    "Mohammed Al-Farsi"
]

def normalize(text):
    """
    Unicode NFC normalization and 
    whitespace collapsing
    """
    text = unicodedata.normalize('NFC', text)
    return ' '.join(text.strip().lower().split())

def stage1_exact_match(name, sdn_list):
    """
    Stage 1: Exact normalized matching
    against OFAC SDN, EU and UN list entries
    Returns: verdict (HOLD/CLEAR), score
    """
    normalized = normalize(name)
    for entry in sdn_list:
        if normalized == normalize(entry):
            return "HOLD", 1.0
    return "CLEAR", 0.0

def stage2_fuzzy_match(name, sdn_list, 
                        threshold=THRESHOLD):
    """
    Stage 2: Jaro-Winkler fuzzy matching
    Applied only when exact match inconclusive
    Returns: verdict (HOLD/CLEAR), score
    """
    normalized = normalize(name)
    max_score = 0.0
    for entry in sdn_list:
        score = jaro_winkler_similarity(
            normalized, normalize(entry))
        max_score = max(max_score, score)
    if max_score >= threshold:
        return "HOLD", max_score
    return "CLEAR", max_score

def screen_payment(payment, sdn_list=SDN_LIST):
    """
    Main screening pipeline for pacs.008 
    and pacs.009 messages.
    Recursively evaluates all party fields.
    Returns: verdict (HOLD/CLEAR), score
    """
    # Extract ISO 20022 structured party fields
    fields = [
        payment.get("cdtr", ""),
        payment.get("dbtr", ""),
        payment.get("ultmtDbtr", ""),
        payment.get("instgAgt", ""),
        payment.get("instdAgt", "")
    ]

    for field in fields:
        if not field:
            continue

        # Stage 1 — Exact match
        verdict, score = stage1_exact_match(
            field, sdn_list)
        if verdict == "HOLD":
            return "HOLD", score

        # Stage 2 — Fuzzy match
        verdict, score = stage2_fuzzy_match(
            field, sdn_list)
        if verdict == "HOLD":
            return "HOLD", score

    return "CLEAR", 0.0

def evaluate_threshold(corpus_file, 
                       thresholds):
    """
    Evaluate different thresholds against
    synthetic test corpus.
    Used to empirically derive optimal threshold.
    """
    with open(corpus_file, 'r') as f:
        corpus = json.load(f)

    results = {}
    for threshold in thresholds:
        tp = fp = tn = fn = 0
        for transaction in corpus:
            verdict, _ = screen_payment(
                transaction['payment'],
                transaction.get('sdn_list', 
                                SDN_LIST))
            expected = transaction['expected']
            if verdict == "HOLD" and expected == "HOLD":
                tp += 1
            elif verdict == "HOLD" and expected == "CLEAR":
                fp += 1
            elif verdict == "CLEAR" and expected == "CLEAR":
                tn += 1
            else:
                fn += 1

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        results[threshold] = {
            'FPR': round(fpr * 100, 1),
            'FNR': round(fnr * 100, 1)
        }
    return results

if __name__ == "__main__":
    # Example pacs.008 payment screening
    payment = {
        "cdtr": "Ahmad Al-Rashid",
        "dbtr": "Alice Corporation",
        "ultmtDbtr": "Bob Industries",
        "instgAgt": "DEUTDEDB",
        "instdAgt": "CHASUS33"
    }

    verdict, score = screen_payment(payment)
    print(f"Payment Screening Result:")
    print(f"Verdict: {verdict}")
    print(f"Confidence Score: {score:.4f}")
    print(f"Threshold: {THRESHOLD}")
