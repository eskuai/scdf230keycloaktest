# Summary about deployment scdf 2.3.0 applying keycloak 8.0.1

I am deploying scdf23 and skipper using default deployment values.<br> 
Configuration obtained from `https://github.com/jvalkeal/randomstuff/blob/master/dataflow-uaa/docker-compose-oauth.yml#L67-L80` [jvalkeal-randomstuff](https://github.com/jvalkeal/randomstuff/blob/master/dataflow-uaa/docker-compose-oauth.yml#L67-L80)
 
*  The scdf-deployment values using keycloak needed to check: 

    1. Applying `SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_KEYCLOAK_USER_NAME_ATTRIBUTE` with value `'preferred_username'` as keycloak info shows.
    1. Applying `SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_KEYCLOAK_CLIENT_NAME` with value `'<keycloak user defined>'`.
    1. Needed `SPRING_SECURITY_OAUTH2_AUTHORIZATION_CHECK_TOKEN_ACCESS` with value `'isAuthenticated()'`.

```
        - name: spring.cloud.dataflow.security.authorization.provider-role-mappings.keycloak.map-oauth-scopes
          value: 'true'
        - name: spring.cloud.dataflow.security.authorization.provider-role-mappings.keycloak.role-mappings.ROLE_CREATE
          value: 'dataflow.create'
        - name: spring.cloud.dataflow.security.authorization.provider-role-mappings.keycloak.role-mappings.ROLE_DEPLOY
          value: 'dataflow.deploy'
        - name: spring.cloud.dataflow.security.authorization.provider-role-mappings.keycloak.role-mappings.ROLE_MODIFY
          value: 'dataflow.modify'
        - name: spring.cloud.dataflow.security.authorization.provider-role-mappings.keycloak.role-mappings.ROLE_MANAGE
          value: 'dataflow.manage'
        - name: spring.cloud.dataflow.security.authorization.provider-role-mappings.keycloak.role-mappings.ROLE_SCHEDULE
          value: 'dataflow.schedule'
        - name: spring.cloud.dataflow.security.authorization.provider-role-mappings.keycloak.role-mappings.ROLE_DESTROY
          value: 'dataflow.destroy'
        - name: spring.cloud.dataflow.security.authorization.provider-role-mappings.keycloak.role-mappings.ROLE_VIEW
          value: 'dataflow.view'
        - name: spring.cloud.dataflow.security.authorization.provider-role-mappings.keycloak.map-oauth-scopes
          value: 'true'
        - name: SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_KEYCLOAK_REDIRECT_URI
          value: '{baseUrl}/login/oauth2/code/{registrationId}'
        - name: SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_KEYCLOAK_AUTHORIZATION_GRANT_TYPE
          value: 'authorization_code'
        - name: SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_KEYCLOAK_CLIENT_NAME
          value: 'mk'
        - name: SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_KEYCLOAK_CLIENT_ID
          value: 'dataflow'
        - name: SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_KEYCLOAK_CLIENT_SECRET
          value: '99fad78e-20f0-4b91-bcaf-0324e34ddf71'       
        - name: SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_KEYCLOAK_SCOPE
          value: 'openid,dataflow.create,dataflow.deploy,dataflow.destroy,dataflow.manage,dataflow.modify,dataflow.schedule,dataflow.view'
        - name: SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_KEYCLOAK_JWK_SET_URI
          value: 'http://keycloak-http:8844/auth/realms/master/protocol/openid-connect/certs'        
        - name: SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_KEYCLOAK_TOKEN_URI
          value: 'http://keycloak-http:8844/auth/realms/master/protocol/openid-connect/token'
        - name: SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_KEYCLOAK_USER_INFO_URI
          value: 'http://keycloak-http:8844/auth/realms/master/protocol/openid-connect/userinfo'
        - name: SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_KEYCLOAK_USER_NAME_ATTRIBUTE
          value: 'preferred_username'         
        - name: SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_KEYCLOAK_AUTHORIZATION_URI
          value: 'http://keycloak-http:8844/auth/realms/master/protocol/openid-connect/auth'         
        - name: SPRING_SECURITY_OAUTH2_RESOURCESERVER_OPAQUETOKEN_INTROSPECTION_URI
          value: 'http://keycloak-http:8844/auth/realms/master/protocol/openid-connect/token/introspect'         
        - name: SPRING_SECURITY_OAUTH2_RESOURCESERVER_OPAQUETOKEN_CLIENT_ID
          value: 'dataflow'
        - name: SPRING_SECURITY_OAUTH2_RESOURCESERVER_OPAQUETOKEN_CLIENT_SECRET
          value: '99fad78e-20f0-4b91-bcaf-0324e34ddf71'         
        - name: SPRING_SECURITY_OAUTH2_AUTHORIZATION_CHECK_TOKEN_ACCESS
          value: 'isAuthenticated()'
```
       



*  The skipper-deployment values using keycloak needed to check (all values are the same to scdf):
    1. Be sure that you dont apply `SPRING_SECURITY_OAUTH2_AUTHORIZATION_CHECK_TOKEN_ACCESS` with value `'isAuthenticated()'`.
    
    
* All config about rules and roles is default values ... nothing changed or updated ...
* At this moment, using the same client to keycloak ... `dataflow`, maybe, using diffentes clients is a best practice

**I got two problems to fix**

1. Problems with `/about` access.<br>
Something, access to `/about/` is forbidden.<br> 
I think is something about `isAuthorized()` properties, because, if it configures in skipper, fails always. 

![/about](screen_about.png)

log info from skipper shows: <br>

```
2020-01-17 16:40:01.250 DEBUG 1 --- [nio-7577-exec-4] o.s.s.w.u.matcher.AntPathRequestMatcher  : Request -GET /api/about- doesnt match -DELETE /logout----
2020-01-17 16:40:01.250 DEBUG 1 --- [nio-7577-exec-4] o.s.s.web.util.matcher.OrRequestMatcher  : No matches found
2020-01-17 16:40:01.250 DEBUG 1 --- [nio-7577-exec-4] o.s.security.web.FilterChainProxy        : /api/about at position 5 of 13 in additional filter chain; firing Filter: -BearerTokenAuthenticationFilter-
2020-01-17 16:40:01.251 DEBUG 1 --- [nio-7577-exec-4] o.s.s.authentication.ProviderManager     : Authentication attempt using org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenAuthenticationProvider
2020-01-17 16:40:01.257 DEBUG 1 --- [nio-7577-exec-4] .s.a.DefaultAuthenticationEventPublisher : No event was found for the exception org.springframework.security.oauth2.core.OAuth2AuthenticationException
2020-01-17 16:40:01.258 DEBUG 1 --- [nio-7577-exec-4] .o.s.r.w.BearerTokenAuthenticationFilter : Authentication request for failed!
org.springframework.security.oauth2.core.OAuth2AuthenticationException: Provided token [eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIyUWlyQi14SEdUb2wxSlBtbkFjbVVFS1JOREN0V2pSeXVrTERac25QZlJ3In0.eyJqdGkiOiJjZTM1NDExNC1mZWVmLTQ5M2EtOTAxZS00MzZiNmQ0MGVmNjMiLCJleHAiOjE1NzkyNzU0NzgsIm5iZiI6MCwiaWF0IjoxNTc5Mjc1NDE4LCJpc3MiOiJodHRwOi8va2V5Y2xvYWstaHR0cDo4ODQ0L2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI2ODI1YmE5Yi0zYzEzLTQ4MWItYmUwMC0zYjA0ZWQ5YmJlZWEiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJkYXRhZmxvdyIsIm5vbmNlIjoiNUNYTy1XODJNeUU5VEQ5eG9rcnZpM3ltVl8zN285ZVlKdWZkcVlNYTR0byIsImF1dGhfdGltZSI6MTU3OTI3NTQxOCwic2Vzc2lvbl9zdGF0ZSI6ImFlZGEzYTI2LWU5MzItNGQyZS04MmY1LTNjZTlmZTQ0N2I0ZSIsImFjciI6IjEiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiIsInNjZGYtcm9sZSJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIGRhdGFmbG93LmRlc3Ryb3kgcHJvZmlsZSBlbWFpbCBkYXRhZmxvdy5tYW5hZ2UgZGF0YWZsb3cuc2NoZWR1bGUgZGF0YWZsb3cuY3JlYXRlIGRhdGFmbG93LmRlcGxveSBkYXRhZmxvdy52aWV3IGRhdGFmbG93Lm1vZGlmeSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoibWsifQ.Vzsl7mCcMEH-aWRA3yPmWDxZZYFN_s8B8PUt6CUkaGP25RiLRHCIoKbpO1BqXvbwncyR2WwYlVWpk8YNZu8FqyQIbPXjWrCn5_FOjPLMd0KEPMB5uZkuHEZgkMMVUgYfOsEBXJRkyqoGqa00tzna7ORymx78i2b9hHoCdQBG5cENIuJu-wkVcBztjkbgq-hgRn_88MMLUVzQurMUoyote6ZPoUW4m8g-IKZi1_bgkvechaFRgexdvGFMfGRzf3HTmKt36-BK1h7jU-7JEkICHyw4KYuhfF9rIMoXm1cgdUftZhGTK6deG83yZmrOwBqjVCVxWLKc9c3HZzgTAgTzOg] isnt active
        at org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenAuthenticationProvider.authenticate(OpaqueTokenAuthenticationProvider.java:99) ~[spring-security-oauth2-resource-server-5.2.1.RELEASE.jar!/:5.2.1.RELEASE]
        at org.springframework.security.authentication.ProviderManager.authenticate(ProviderManager.java:175) ~[spring-security-core-5.2.1.RELEASE.jar!/:5.2.1.RELEASE]
        at org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter.doFilterInternal(BearerTokenAuthenticationFilter.java:124) ~[spring-security-oauth2-resource-server-5.2.1.RELEASE.jar!/:5.2.1.RELEASE]
        at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:119) [spring-web-5.2.1.RELEASE.jar!/:5.2.1.RELEASE]
        at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:334) [spring-security-web-5.2.1.RELEASE.jar!/:5.2.1.RELEASE]
        at org.springframework.security.web.authentication.logout.LogoutFilter.doFilter(LogoutFilter.java:116) [spring-security-web-5.2.1.RELEASE.jar!/:5.2.1.RELEASE]
        at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:334) [spring-security-web-5.2.1.RELEASE.jar!/:5.2.1.RELEASE]
        
```

1. dashboard streaming doesn't work.<br>


![/about](screen_skipper.png)
    