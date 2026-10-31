from cybersentinel.agents.adaptive_defense import AdaptiveDefenseAgent


def test_defense_initial_flow_allowed():
    agent = AdaptiveDefenseAgent(default_duration=10)
    # First flow: no prior policy
    pre_filter = agent.evaluate_pre_filter(record_id="rec-0", source_ip="192.168.1.1", current_step=0)
    assert pre_filter is None

    # Benign flow post analysis
    decision = agent.handle_post_analysis(
        record_id="rec-0",
        source_ip="192.168.1.1",
        current_step=0,
        attack_detected=False,
    )
    assert decision.action == "ALLOW"
    assert decision.applied_policy_id == ""
    assert decision.new_policy_created is None


def test_defense_policy_creation_and_blocking():
    agent = AdaptiveDefenseAgent(default_duration=5)
    src_ip = "192.168.1.99"

    # Step 0: Initial attack flow -> Allowed into analyzer, triggers future policy
    pre = agent.evaluate_pre_filter(record_id="rec-0", source_ip=src_ip, current_step=0)
    assert pre is None

    decision0 = agent.handle_post_analysis(
        record_id="rec-0",
        source_ip=src_ip,
        current_step=0,
        attack_detected=True,
        attack_type="DOS",
        confidence=0.95,
    )
    assert decision0.action == "ALLOW"
    assert decision0.new_policy_created is not None
    policy_id = decision0.new_policy_created.policy_id
    assert policy_id.startswith("POL-")
    assert decision0.new_policy_created.scope_type == "SOURCE_IP"
    assert decision0.new_policy_created.scope_value == src_ip
    assert decision0.new_policy_created.expires_after_record_id == 5

    # Step 1: Second flow from same attacker -> Blocked by active policy!
    pre1 = agent.evaluate_pre_filter(record_id="rec-1", source_ip=src_ip, current_step=1)
    assert pre1 is not None
    assert pre1.action == "BLOCK"
    assert pre1.applied_policy_id == policy_id
    assert pre1.is_pre_filtered is True


def test_defense_policy_expiration():
    agent = AdaptiveDefenseAgent(default_duration=3)
    src_ip = "192.168.1.44"

    # Activate policy at step 0, expires at step 3
    agent.handle_post_analysis(
        record_id="rec-0",
        source_ip=src_ip,
        current_step=0,
        attack_detected=True,
        attack_type="PORT_SCAN",
    )

    # At step 2: Still blocked
    pre_active = agent.evaluate_pre_filter(record_id="rec-2", source_ip=src_ip, current_step=2)
    assert pre_active is not None
    assert pre_active.action == "BLOCK"

    # At step 4: Expired!
    pre_expired = agent.evaluate_pre_filter(record_id="rec-4", source_ip=src_ip, current_step=4)
    assert pre_expired is None



def test_defense_does_not_create_policy_without_source_identity():
    agent = AdaptiveDefenseAgent(default_duration=10)
    decision = agent.handle_post_analysis(
        record_id="rec-no-source",
        source_ip="",
        current_step=0,
        attack_detected=True,
        attack_type="DOS",
        confidence=0.99,
    )
    assert decision.action == "ALLOW"
    assert decision.new_policy_created is None
    assert agent.all_policies == []


def test_defense_rejects_fingerprint_or_non_ip_scope():
    agent = AdaptiveDefenseAgent(default_duration=10)
    for identity in ("10.1.2.3-derived", "host-fingerprint-abc", ""):
        decision = agent.handle_post_analysis(
            record_id="rec-1", source_ip=identity, current_step=0,
            attack_detected=True, attack_type="DOS", confidence=0.99,
        )
        assert decision.new_policy_created is None
    assert agent.all_policies == []
