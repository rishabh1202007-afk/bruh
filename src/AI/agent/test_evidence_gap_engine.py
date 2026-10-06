from AI.agent.evidence_gap_engine import EvidenceGapEngine

def test_empty_packet():
    a=EvidenceGapEngine().analyze({})
    assert a.gaps == [] and a.visibility_score == 100 and a.sufficient_for_investigation

def test_windows_detection_without_raw_event():
    a=EvidenceGapEngine().analyze({'detections':[{'detection_id':'SM-002'}]})
    assert any(g.gap_id=='GAP-RAW-WINDOWS' and g.blocking for g in a.gaps)

def test_behavior_detection_without_telemetry():
    a=EvidenceGapEngine().analyze({'behavior_detections':[{'behavior_detection_id':'BT-003'}]})
    assert any(g.gap_id=='GAP-BEHAVIOR-TELEMETRY' and g.blocking for g in a.gaps)

def test_process_gap_and_synthetic_context():
    a=EvidenceGapEngine().analyze({'events':[{'raw_data':['x']}], 'detections':[{'rule_name':'Suspicious Script Execution'}], 'behaviors':[{'synthetic':True}]})
    assert any(g.gap_id=='GAP-PROCESS-CONTEXT' and not g.blocking for g in a.gaps)
    assert any(g.gap_id=='GAP-SYNTHETIC-CONTEXT' for g in a.gaps)

def test_network_gap():
    a=EvidenceGapEngine().analyze({'events':[{'raw_data':['x']}], 'detections':[{'rule_name':'Possible Command and Control Activity'}]})
    assert any(g.gap_id=='GAP-NETWORK-CONTEXT' and g.blocking for g in a.gaps)

def test_raw_context_avoids_windows_gap():
    a=EvidenceGapEngine().analyze({'events':[{'event_id':'EV-1','raw_data':['4679']}], 'detections':[{'detection_id':'SM-002'}]})
    assert not any(g.gap_id=='GAP-RAW-WINDOWS' for g in a.gaps)

def test_behavior_telemetry_avoids_behavior_gap():
    a=EvidenceGapEngine().analyze({'behavior_detections':[{'behavior_detection_id':'BT-003'}], 'behaviors':[{'telemetry_id':'TEL-1','behavior_type':'browser_data_access'}]})
    assert not any(g.gap_id=='GAP-BEHAVIOR-TELEMETRY' for g in a.gaps)
