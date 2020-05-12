namespace PgpCore
{
    public enum PgpSignatureType
    {
        BinaryDocument = 0,
        CanonicalTextDocument = 1,
        StandAlone = 2,
        DefaultCertification = 16,
        NoCertification = 17,
        CasualCertification = 18,
        PositiveCertification = 19,
        SubkeyBinding = 24,
        PrimaryKeyBinding = 25,
        DirectKey = 31,
        KeyRevocation = 32,
        SubkeyRevocation = 40,
        CertificationRevocation = 48,
        Timestamp = 64
    }
}
