//! Whereabouts trusts kernel network and process events because Windows does
//! not let ordinary programs register those provider IDs. This test checks
//! that on every machine it runs on, including CI's Windows Server runners.
//! It needs no administrator rights and writes no events.

use whereabouts_win_capture::dns::DNS_CLIENT_PROVIDER;
use whereabouts_win_capture::events::{KERNEL_NETWORK_PROVIDER_ID, KERNEL_PROCESS_PROVIDER_ID};
use whereabouts_win_capture::protection::{Registration, kernel_providers_protected, try_register};

#[test]
fn kernel_provider_ids_cannot_be_registered() {
    for (name, provider) in [
        ("Kernel-Network", KERNEL_NETWORK_PROVIDER_ID),
        ("Kernel-Process", KERNEL_PROCESS_PROVIDER_ID),
    ] {
        let result = try_register(provider);
        assert!(
            matches!(result, Registration::Refused(_)),
            "{name} provider ID could be registered ({result:?}): its events could be faked"
        );
    }
    assert!(kernel_providers_protected());
}

#[test]
fn the_check_can_tell_an_unprotected_provider_apart() {
    // The DNS Client provider ID *can* be registered by any program, which
    // is why DNS labels are verified separately. This shows the check above
    // is not passing just because every registration fails.
    let dns = u128::from_str_radix(&DNS_CLIENT_PROVIDER.replace('-', ""), 16).unwrap();
    assert_eq!(try_register(dns), Registration::Allowed);
}
