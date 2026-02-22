package burp;

/**
 * Burp legacy extension loader entrypoint.
 *
 * Burp historically expects a public class named "BurpExtender" in the "burp" package.
 * We keep the implementation in {@link BionicLink} and extend it here.
 */
public final class BurpExtender extends BionicLink {
    // No-op.
}

