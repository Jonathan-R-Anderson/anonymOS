import kernel.ipc.secure_ipc;
import std.conv : to;

void main()
{
    auto kp1 = dh_generate(7);
    auto kp2 = dh_generate(13);
    assert(dh_compute_shared(kp2.pub, kp1.priv) == dh_compute_shared(kp1.pub, kp2.priv));
    auto secret = dh_compute_shared(kp2.pub, kp1.priv);

    SecureSession s1, s2;
    session_init(s1, secret, 0xdeadbeef);
    session_init(s2, secret, 0xdeadbeef);

    ubyte[] msg = cast(ubyte[])[1,2,3,4];
    auto sig = sign_message(s1, msg);
    encrypt(s1, msg);
    decrypt(s2, msg);
    assert(verify_message(s2, msg, sig));

    RendezvousInfo a,b;
    prepare_rendezvous(a, "foo");
    prepare_rendezvous(b, "foo");
    assert(verify_rendezvous(a,b));
}
