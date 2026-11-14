from scripts.prepare_public_benchmark import (
    DATASET_REVISION,
    LABEL_MAP,
    canonical_label,
)


def test_public_cicids_mapping_covers_only_documented_five_class_subset():
    assert canonical_label("BENIGN") == "BENIGN"
    assert canonical_label("FTP-Patator") == "BRUTE_FORCE"
    assert canonical_label("SSH-Patator") == "BRUTE_FORCE"
    assert canonical_label("DoS Hulk") == "DOS"
    assert canonical_label("DoS GoldenEye") == "DOS"
    assert canonical_label("DoS slowloris") == "DOS"
    assert canonical_label("DoS Slowhttptest") == "DOS"
    assert canonical_label("DDoS") == "DDOS"
    assert canonical_label("PortScan") == "PORT_SCAN"


def test_public_cicids_mapping_does_not_silently_relabel_other_attack_families():
    for label in ("Bot", "Infiltration", "Heartbleed", "Web Attack - XSS", "Web Attack - Sql Injection"):
        assert canonical_label(label) is None


def test_public_dataset_revision_is_pinned_and_mapping_is_exact():
    assert len(DATASET_REVISION) == 40
    assert set(LABEL_MAP.values()) == {"BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"}
