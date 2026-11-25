use super::*;
#[test]
fn negotiation_does_not_widen_authority() {
    let offer = vec![(CAP, Selection::offer().value())];
    assert!(check(&offer, &offer).is_ok());
    for modes in [vec![1, 1], vec![], vec![4]] {
        let mut s = Selection::offer();
        s.modes = modes;
        assert!(check(&vec![(CAP, s.value())], &offer).is_err())
    }
    let mut s = Selection::offer();
    s.flows += 1;
    assert!(check(&vec![(CAP, s.value())], &offer).is_err());
    assert!(check(&offer, &vec![]).is_err());
}
#[test]
fn addresses_and_rules_are_strict() {
    for s in ["a b:80", "a..b:80", "-a:80", "a:0", "[::1%3]:80", "é.fr:80"] {
        assert!(s.parse::<Target>().is_err(), "{s}")
    }
    for s in ["127.0.0.1:22", "[::1]:22", "Example.COM.:443"] {
        let t = s.parse::<Target>().unwrap();
        assert_eq!(Target::parse(&t.value(), false).unwrap(), t)
    }
    assert!(
        !"[::ffff:127.0.0.1]:22"
            .parse::<Target>()
            .unwrap()
            .value()
            .as_array()
            .unwrap()
            .is_empty()
    );
    let t = "localhost:22".parse::<Target>().unwrap();
    assert!(
        Rule::parse(
            &Rule {
                mode: 2,
                target: Some(t),
                bind: Some("127.0.0.1:0".parse().unwrap())
            }
            .message()
        )
        .is_err()
    );
    assert!(Target::parse(&socket_value("127.0.0.1:0".parse().unwrap()), false).is_err());
}
#[test]
fn policy_denies_by_default_and_normalizes_candidates() {
    let config: Config = toml::from_str(
        r#"[accounts.alice]
local=true
names=["db.example"]
targets=[{network="127.0.0.0/8",ports=[5432]}]
binds=[{network="::1/128"}]
"#,
    )
    .unwrap();
    let p = &config.accounts["alice"];
    assert!(p.target(&"127.1.2.3:5432".parse().unwrap()));
    assert!(!p.target(&"127.1.2.3:80".parse().unwrap()));
    assert!(!p.target(&"db.other:5432".parse().unwrap()));
    assert!(!p.targets[0].allows("10.0.0.1:5432".parse().unwrap()));
    assert!(p.targets[0].allows("[::ffff:127.0.0.1]:5432".parse().unwrap()));
    assert!(!Policy::default().target(&"127.0.0.1:22".parse().unwrap()));
    assert!(toml::from_str::<Config>("[accounts.x]\nlocla=true").is_err());
}
#[test]
fn reply_validation_and_network_edges() {
    assert!(outcome(&Status::Denied.reply(CONNECTED, None), CONNECTED, true).is_ok());
    assert!(outcome(&Status::Ok.reply(CONNECTED, None), CONNECTED, true).is_err());
    assert!(
        outcome(
            &Status::Denied.reply(READY, Some("127.0.0.1:1".parse().unwrap())),
            READY,
            false
        )
        .is_err()
    );
    assert!(
        "0.0.0.0/0"
            .parse::<Net>()
            .unwrap()
            .contains("10.1.2.3".parse().unwrap())
    );
    assert!(
        !"::/0"
            .parse::<Net>()
            .unwrap()
            .contains("127.0.0.1".parse().unwrap())
    );
    assert!("::/129".parse::<Net>().is_err());
}
