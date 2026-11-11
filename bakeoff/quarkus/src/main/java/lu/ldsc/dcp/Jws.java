// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

package lu.ldsc.dcp;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/** Compact JWS signing and verification. Only ES256 and PS256 are accepted. */
public final class Jws {
    private static final com.fasterxml.jackson.databind.ObjectMapper MAPPER = new com.fasterxml.jackson.databind.ObjectMapper();
    private static final Base64.Decoder DEC = Base64.getUrlDecoder();
    private static final Base64.Encoder ENC = Base64.getUrlEncoder().withoutPadding();

    private Jws() {}

    public enum Alg { ES256, PS256 }

    public record Parsed(String signingInput, byte[] signature, Alg alg, String headerJson, String payloadJson) {}

    public static Parsed parse(String token) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new IllegalArgumentException("malformed token");
        }
        String header = new String(DEC.decode(parts[0]), StandardCharsets.UTF_8);
        String algName;
        try {
            algName = MAPPER.readTree(header).path("alg").asText("");
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException("malformed header", e);
        }
        Alg alg = switch (algName) {
            case "ES256" -> Alg.ES256;
            case "PS256" -> Alg.PS256;
            default -> throw new IllegalArgumentException("algorithm not allowed: " + algName);
        };
        return new Parsed(parts[0] + "." + parts[1], DEC.decode(parts[2]), alg, header,
                new String(DEC.decode(parts[1]), StandardCharsets.UTF_8));
    }

    static Signature signer(Alg alg) throws GeneralSecurityException {
        if (alg == Alg.ES256) {
            return Signature.getInstance("SHA256withECDSAinP1363Format");
        }
        Signature s = Signature.getInstance("RSASSA-PSS");
        s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        return s;
    }

    public static String sign(Alg alg, PrivateKey key, String headerJson, String payloadJson) throws GeneralSecurityException {
        String input = ENC.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8)) + "."
                + ENC.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        Signature s = signer(alg);
        s.initSign(key);
        s.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + ENC.encodeToString(s.sign());
    }

    public static boolean verify(Parsed jws, PublicKey key) throws GeneralSecurityException {
        Signature s = signer(jws.alg());
        s.initVerify(key);
        s.update(jws.signingInput().getBytes(StandardCharsets.US_ASCII));
        return s.verify(jws.signature());
    }

    public static PublicKey rsaPublicKey(byte[] n, byte[] e) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(new BigInteger(1, n), new BigInteger(1, e)));
    }
}
