// SPDX-FileCopyrightText: Portitor contributors
//
// SPDX-License-Identifier: Apache-2.0

package portitor.interop.edc;

import org.eclipse.edc.connector.controlplane.dataplane.spi.instance.AuthorizationProfile;
import org.eclipse.edc.runtime.metamodel.annotation.Inject;
import org.eclipse.edc.signaling.spi.authorization.Header;
import org.eclipse.edc.signaling.spi.authorization.SignalingAuthorization;
import org.eclipse.edc.signaling.spi.authorization.SignalingAuthorizationRegistry;
import org.eclipse.edc.spi.result.Result;
import org.eclipse.edc.spi.system.ServiceExtension;
import org.eclipse.edc.spi.system.ServiceExtensionContext;

import java.util.function.Function;

/**
 * Test only: lets the control plane and the test data plane talk Data
 * Plane Signaling without authentication (profile type "none"). Both run
 * on the private Compose network of the interop test. EDC's Minimum
 * Viable Dataspace does the same (extension "signaling-auth-none").
 */
public class NoneSignalingAuthorizationExtension implements ServiceExtension {

    @Inject
    private SignalingAuthorizationRegistry registry;

    @Override
    public String name() {
        return "Portitor interop test: signaling without authorization";
    }

    @Override
    public void initialize(ServiceExtensionContext context) {
        registry.register(new NoneAuthorization());
    }

    private static final class NoneAuthorization implements SignalingAuthorization {
        @Override
        public String getType() {
            return "none";
        }

        @Override
        public Result<String> isAuthorized(Function<String, String> headerGetter, AuthorizationProfile profile) {
            return Result.success("none");
        }

        @Override
        public Result<Header> evaluate(AuthorizationProfile profile) {
            return Result.success(new Header("Authorization", "Bearer none"));
        }
    }
}
