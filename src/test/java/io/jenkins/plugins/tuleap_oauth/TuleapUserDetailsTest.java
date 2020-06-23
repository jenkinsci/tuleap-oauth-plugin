package io.jenkins.plugins.tuleap_oauth;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.junit.Test;
import static org.junit.Assert.*;

public class TuleapUserDetailsTest {

    @Test
    public void testItShouldConcatenateAllAuthorities() {
        TuleapUserDetails tuleapUserDetails = new TuleapUserDetails("a User");

        tuleapUserDetails.addAuthority(new GrantedAuthorityImpl("authenticated"));
        tuleapUserDetails.addTuleapAuthority(new GrantedAuthorityImpl("use-me#project_members"));

        GrantedAuthority[] authorities = tuleapUserDetails.getAuthorities();

        assertEquals(authorities.length, 2);
        assertEquals(authorities[0].getAuthority(), "authenticated");
        assertEquals(authorities[1].getAuthority(), "use-me#project_members");
    }
}
