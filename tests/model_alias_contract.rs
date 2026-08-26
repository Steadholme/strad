use strad::config::valid_model_alias;

#[test]
fn model_alias_contract_accepts_supported_real_world_shapes() {
    for alias in ["glm-5.2", "vendor/name:v1", "A_Z-9/model.name:v2"] {
        assert!(valid_model_alias(alias), "expected {alias:?} to be valid");
    }
}

#[test]
fn model_alias_contract_enforces_ascii_length_boundaries() {
    let max_length_alias = "a".repeat(128);
    let over_length_alias = "a".repeat(129);

    assert!(valid_model_alias(&max_length_alias));
    assert!(!valid_model_alias(&over_length_alias));
}

#[test]
fn model_alias_contract_rejects_empty_or_unsafe_values() {
    for alias in ["", "model with spaces", "model?query", "模型"] {
        assert!(
            !valid_model_alias(alias),
            "expected {alias:?} to be invalid"
        );
    }
}
