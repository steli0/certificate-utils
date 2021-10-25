package cu.client

import org.eclipse.microprofile.rest.client.inject.RegisterRestClient
import javax.ws.rs.GET
import javax.ws.rs.Path
import javax.ws.rs.Produces
import javax.ws.rs.core.Response

@RegisterRestClient
interface RestService {
    @GET
    @Path("/health")
    @Produces("text/plain")
    fun health(): Response
}
