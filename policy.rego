# ABAC Policy Rules for ZTA ISO 20022
# Open Policy Agent (OPA) v0.61
# Zero Trust Architecture Framework

package iso20022.zta

# Default deny all
default allow = false

# Allow pacs.008 Originating to Clearing
allow {
    input.message_type == "pacs.008"
    input.source_zone == "originating"
    input.target_zone == "clearing"
    input.screening_verdict == "CLEAR"
    input.risk_score < input.risk_threshold
    valid_lei(input.sender_lei)
}

# Allow pacs.009 Clearing to Clearing only
allow {
    input.message_type == "pacs.009"
    input.source_zone == "clearing"
    input.target_zone == "clearing"
    input.screening_verdict == "CLEAR"
    input.risk_score < input.risk_threshold
    valid_lei(input.sender_lei)
}

# Allow camt.056 Compliance Zone only
allow {
    input.message_type == "camt.056"
    input.target_zone == "compliance"
    input.screening_verdict == "CLEAR"
    valid_lei(input.sender_lei)
}

# Block direct Originating to Beneficiary
deny {
    input.source_zone == "originating"
    input.target_zone == "beneficiary"
}

# Block all payment zones from Compliance
deny {
    input.source_zone != "compliance"
    input.target_zone == "compliance"
    input.message_type != "camt.056"
}

# LEI validation helper
valid_lei(lei) {
    count(lei) == 20
    regex.match(
        "^[A-Z0-9]{18}[0-9]{2}$", lei)
}

# Risk score evaluation
high_risk {
    input.risk_score >= input.risk_threshold
}

# Time based risk elevation
elevated_risk {
    input.hour < 6
    input.hour > 22
}
