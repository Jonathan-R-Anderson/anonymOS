// YARA rules for Go-based Linux C2 Implants (Sliver, Merlin, Poseidon)

rule Go_Implant_Sliver : malware sliver c2 {
    meta:
        description = "Detects Sliver Go-based C2 framework agent"
        author = "Orin Security"
        severity = "critical"
        attack = "T1105"
    strings:
        $s1 = "sliverpb." ascii
        $s2 = "github.com/bishopfox/sliver" ascii
        $s3 = "Sliver (*" ascii
        $s4 = "go.uuid.NewV4" ascii
    condition:
        2 of them
}

rule Go_Implant_Merlin : malware merlin c2 {
    meta:
        description = "Detects Merlin Go-based HTTP/2 C2 agent"
        author = "Orin Security"
        severity = "critical"
        attack = "T1105"
    strings:
        $m1 = "merlinpb" ascii
        $m2 = "github.com/Ne0nd0g/merlin" ascii
        $m3 = "merlin-agent" ascii
    condition:
        any of them
}

rule Go_Implant_Poseidon : malware poseidon c2 {
    meta:
        description = "Detects Poseidon Go-based agent for Mythic C2"
        author = "Orin Security"
        severity = "critical"
        attack = "T1105"
    strings:
        $p1 = "github.com/its-a-feature/Poseidon" ascii
        $p2 = "poseidon.CheckIn" ascii
        $p3 = "poseidonHost" ascii
    condition:
        any of them
}
