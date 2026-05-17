from sec_assess.core.finding import Finding
from sec_assess.core.risk_engine import RiskEngine
from sec_assess.core.severity import Severity


def make_finding(severity: Severity) -> Finding:
    return Finding(
        id="TEST-001",
        title="Test finding",
        severity=severity,
        category="Test",
        description="Test description",
        evidence="Test evidence",
        recommendation="Test recommendation",
        target="https://example.com",
    )


def test_risk_score_without_findings_is_100():
    engine = RiskEngine()

    score = engine.calculate_score([])

    assert score == 100


def test_risk_score_with_medium_and_high_findings():
    engine = RiskEngine()
    findings = [
        make_finding(Severity.MEDIUM),
        make_finding(Severity.HIGH),
    ]

    score = engine.calculate_score(findings)

    assert score == 77


def test_risk_score_never_goes_below_zero():
    engine = RiskEngine()
    findings = [make_finding(Severity.CRITICAL) for _ in range(10)]

    score = engine.calculate_score(findings)

    assert score == 0


def test_classify_low_risk():
    engine = RiskEngine()

    assert engine.classify_risk(90) == "LOW"


def test_classify_medium_risk():
    engine = RiskEngine()

    assert engine.classify_risk(70) == "MEDIUM"


def test_classify_high_risk():
    engine = RiskEngine()

    assert engine.classify_risk(50) == "HIGH"


def test_classify_critical_risk():
    engine = RiskEngine()

    assert engine.classify_risk(20) == "CRITICAL"


def test_classify_risk_with_high_finding_returns_high():
    engine = RiskEngine()
    findings = [make_finding(Severity.HIGH)]

    score = engine.calculate_score(findings)
    risk = engine.classify_risk(score, findings)

    assert score == 85
    assert risk == "HIGH"


def test_classify_risk_with_critical_finding_returns_critical():
    engine = RiskEngine()
    findings = [make_finding(Severity.CRITICAL)]

    score = engine.calculate_score(findings)
    risk = engine.classify_risk(score, findings)

    assert score == 75
    assert risk == "CRITICAL"


def test_classify_risk_with_medium_finding_returns_medium():
    engine = RiskEngine()
    findings = [make_finding(Severity.MEDIUM)]

    score = engine.calculate_score(findings)
    risk = engine.classify_risk(score, findings)

    assert score == 92
    assert risk == "MEDIUM"
    
def test_count_by_severity():
    engine = RiskEngine()
    findings = [
        make_finding(Severity.INFO),
        make_finding(Severity.LOW),
        make_finding(Severity.LOW),
        make_finding(Severity.HIGH),
    ]

    counts = engine.count_by_severity(findings)

    assert counts["INFO"] == 1
    assert counts["LOW"] == 2
    assert counts["MEDIUM"] == 0
    assert counts["HIGH"] == 1
    assert counts["CRITICAL"] == 0
    
    