package circuit

// goldenKeySchedule pins the axon-ntor-v1 key schedule (T5.4).
//
// It is the hex concatenation of Kf ‖ Kb ‖ Af ‖ Ab ‖ NPf ‖ NPb ‖ AUTH derived
// from the fixed inputs in TestKeyScheduleGoldenVectors. Any change to a
// domain-separation label, to the secret_input concatenation order, or to the
// 136-byte split changes this string and fails the build -- which is the point:
// a silent KDF change produces relays that cannot talk to the deployed network
// and gives no other signal.
const goldenKeySchedule = "9129988d0d37748d8126bbb20d817ac45dbd650a9d50a7693116515be97fff2fa2458f0c23ae32b8048cfb1b795c7dbec2acc940354bc9cb6990f8ee2746fdb1e812919af063f6327e81132a4c08ae6fe9c07251c878c7a3aac392fdda11584ef92f24db8564f401ee48c76c1082f5f38938dbb323634de85b478b469004881700b660786e33f51508ade4fe90bdaeb878c0d7cc3723a0a8be1fb4b456af425e3b93ee972da3e9c4"
