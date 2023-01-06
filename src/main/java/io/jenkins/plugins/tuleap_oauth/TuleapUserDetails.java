package io.jenkins.plugins.tuleap_oauth;


import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

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
    public Collection<? extends GrantedAuthority> getAuthorities() {
        this.authorities.addAll(this.tuleapAuthorities);
        return this.authorities;
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
