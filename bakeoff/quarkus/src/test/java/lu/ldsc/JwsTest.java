// SPDX-FileCopyrightText: LDSC contributors
//
// SPDX-License-Identifier: Apache-2.0

package lu.ldsc;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import lu.ldsc.dcp.Jws;
import org.junit.jupiter.api.Test;

class JwsTest {
    @Test
    void es256_self_issued_token_round_trip_and_tamper() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = g.generateKeyPair();
        String claims = "{\"iss\":\"did:web:alice.example\",\"sub\":\"did:web:alice.example\",\"aud\":\"did:web:bob.example\",\"jti\":\"j-1\",\"exp\":2000,\"iat\":1000}";
        String t = Jws.sign(Jws.Alg.ES256, kp.getPrivate(), "{\"alg\":\"ES256\",\"kid\":\"did:web:alice.example#key-1\"}", claims);
        assertTrue(Jws.verify(Jws.parse(t), kp.getPublic()));
        String tampered = t.substring(0, t.indexOf('.') + 2) + "A" + t.substring(t.indexOf('.') + 3);
        assertFalse(safeVerify(tampered, kp));
    }

    private static boolean safeVerify(String t, KeyPair kp) {
        try {
            return Jws.verify(Jws.parse(t), kp.getPublic());
        } catch (Exception e) {
            return false;
        }
    }

    @Test
    void rejects_alg_none_and_hs256() {
        for (String alg : new String[] {"none", "HS256"}) {
            String h = Base64.getUrlEncoder().withoutPadding().encodeToString(("{\"alg\":\"" + alg + "\"}").getBytes(StandardCharsets.UTF_8));
            assertThrows(IllegalArgumentException.class, () -> Jws.parse(h + ".e30."));
        }
    }

    @Test
    void ps256_gaia_x_vc_jwt() throws Exception {
        byte[] der = JwsTest.class.getResourceAsStream("/test-only-rsa-2048.pk8").readAllBytes();
        RSAPrivateCrtKey key = (RSAPrivateCrtKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        String vc = "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiableCredential\"],\"issuer\":\"did:web:issuer.example\"}";
        String t = Jws.sign(Jws.Alg.PS256, key, "{\"alg\":\"PS256\",\"typ\":\"vc+jwt\",\"cty\":\"vc\",\"kid\":\"did:web:issuer.example#key-1\"}", vc);
        var pub = Jws.rsaPublicKey(key.getModulus().toByteArray(), key.getPublicExponent().toByteArray());
        assertTrue(Jws.verify(Jws.parse(t), pub));
    }
}
