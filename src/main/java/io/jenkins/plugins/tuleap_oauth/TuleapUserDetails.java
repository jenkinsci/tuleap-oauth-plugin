package io.jenkins.plugins.tuleap_oauth;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public class TuleapUserDetails implements UserDetails {

    private final String username;
    private final ArrayList<GrantedAuthority> authorities;
    private final ArrayList<GrantedAuthority> tuleapAuthorities;

    public TuleapUserDetails(final String username) {
        this.username = username;
        this.authorities = new ArrayList<>();
        this.tuleapAuthorities = new ArrayList<>();
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        return Stream
            .concat(this.authorities.stream(), this.tuleapAuthorities.stream())
            .toArray(GrantedAuthority[]::new);
    }

    public List<GrantedAuthority> getTuleapAuthorities() {
        return this.tuleapAuthorities;
    }

    public void addAuthority(GrantedAuthority authority) {
        this.authorities.add(authority);
    }

    public void addTuleapAuthority(GrantedAuthority tuleapAuthority) {
        this.tuleapAuthorities.add(tuleapAuthority);
    }

    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean equals(Object rhs) {
        return super.equals(rhs);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
