package com.example.practice1.security;

import com.example.practice1.controller.CustomSuccessHandler;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    //Định nghĩa người dùng (tên đăng nhập, hàm băm mật khẩu, vai trò) để xác thực trong bộ nhớ.
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password("{noop}12345").roles("USER")
                .and()
                .withUser("admin").password("{noop}12345").roles("ADMIN")
                .and()
                .withUser("dba").password("{noop}12345").roles("ADMIN", "DBA");
    }

    //Định nghĩa các mẫu URL và quy tắc kiểm soát quyền truy cập:
    ///, /home: Người dùng có vai trò "USER" mới truy cập được.
    ///admin/**: Người dùng có vai trò "ADMIN" mới truy cập được.
    ///dba/**: Người dùng có vai trò "ADMIN" hoặc "DBA" (bất kỳ vai trò nào trong số đó) mới truy cập được.
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .requestMatchers("/", "/home").hasRole("USER")
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/dba/**").hasAnyRole("ADMIN", "DBA")
                .and()
                .formLogin().successHandler(new CustomSuccessHandler())
                .usernameParameter("ssoId").passwordParameter("password")
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .and().exceptionHandling().accessDeniedPage("/accessDenied");
    }
}