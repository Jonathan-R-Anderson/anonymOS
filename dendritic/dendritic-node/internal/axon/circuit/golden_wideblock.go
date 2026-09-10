package circuit

// Golden vectors for the P5a wide-block permutation (T5a.5).
//
// goldenWideBlock is SHA-256 over one fixed block enciphered under a fixed key
// at a fixed tweak. goldenRoundKeys is SHA-256 over the four derived round keys.
// Together they pin the HKDF label, the round order, the branch split, the tweak
// encoding and the per-round domain separation.
const (
	goldenWideBlock = "c9edfa10593afe916b9b5eb53e19a8c39678bb1c651e03f18eba35fc70722d63"
	goldenRoundKeys = "0e26f9839d6a1315fc29693e01b7a5e7c9d194e769eae5d1194609cd523e0314"
)
