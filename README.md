# Zero Trust Architecture for ISO 20022 Cross-Border Payment Networks

## Overview
Proof-of-concept implementation of a Zero Trust 
Architecture framework for ISO 20022 cross-border 
payment networks featuring deterministic sanctions 
screening and micro-segmentation.

## Repository Contents
- `screening.py` — Deterministic sanctions screening pipeline
- `test_corpus.json` — Synthetic pacs.008 test corpus
- `policy.rego` — ABAC policy rules (OPA v0.61)
- `zone_policy.yaml` — Zone transition policy

## Requirements
- Python 3.11+
- jellyfish library

## Installation
pip install jellyfish

## Usage
python screening.py

## Note on Test Corpus
The repository includes a representative sample of the synthetic test corpus. 
The full corpus of 10,000 transactions used in the paper evaluation is available 
upon request.

## Disclaimer
All test data is completely synthetic.
No real payment data is included.
