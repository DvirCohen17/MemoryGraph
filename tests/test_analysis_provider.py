from app.analysis.demo_provider import DemoProvider


def test_demo_provider_returns_normalized_investigation():
    result = DemoProvider().run("demo.raw")
    assert result.processes and result.timeline and result.plugins
    ids = {i.rule_id for i in result.indications}
    assert {"CL-001", "MEM-001", "PR-001", "HND-001", "CORR-001"} <= ids
    assert result.warnings == []


def test_benign_scenario_has_no_findings():
    result = DemoProvider().run("demo.raw", scenario="benign")
    assert result.indications == []


def test_demo_attack_chain_is_correlated_once_per_process():
    result = DemoProvider().run("demo.raw")
    corr = [i for i in result.indications if i.rule_id == "CORR-001" and i.process_pid == 4216]
    assert len(corr) == 1
    assert len(result.indications) < 20          # no finding spam
