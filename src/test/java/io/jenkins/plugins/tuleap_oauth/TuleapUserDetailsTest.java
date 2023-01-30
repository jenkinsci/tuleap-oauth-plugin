package io.jenkins.plugins.tuleap_oauth;

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;

import static org.junit.Assert.*;

public class TuleapUserDetailsTest {

    @Test
    public void testItShouldConcatenateAllAuthorities() {
        TuleapUserDetails tuleapUserDetails = new TuleapUserDetails("a User");

        GrantedAuthority authority1 = new SimpleGrantedAuthority("authenticated");
        tuleapUserDetails.addAuthority(authority1);

        GrantedAuthority authority2 = new SimpleGrantedAuthority("use-me#project_members");
        tuleapUserDetails.addTuleapAuthority(authority2);

        Collection<? extends GrantedAuthority> authorities = tuleapUserDetails.getAuthorities();

        assertEquals(authorities.size(), 2);
        assertTrue(authorities.contains(authority1));
        assertTrue(authorities.contains(authority2));
    }
}
