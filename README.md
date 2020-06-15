# Getting Started

SSL mutual authentication (X.509 Spring Boot Spring Security authentication demo).

Autenticação com e-CPF (https://www.iti.gov.br/icp-brasil). Pode ser adaptado para e-CNPJ.

## Deploy

Update/build
```
$ git pull
$ docker build -t mutual-authentication .
```

Run
```
$ docker run -d --name mutual-authentication --restart unless-stopped -p 443:8443 -p 80:8080 mutual-authentication
```

or 

```
docker pull barrosbruno/votacao:latest
```

or 

```
$ ./mvnw spring-boot:run 
```

##Server certificate

See https://www.baeldung.com/x-509-authentication-in-spring-security.

##Client certificate (e-CPF)

Gerar certificados de teste (A3) para autenticação na aplicação via certificado do cliente (e-CPF).

```
Run com.example.mutualauthentication.util.CriarAcTest
Run com.example.mutualauthentication.util.CriarCertificadoTest
```
## Use

dev profile
```
$ curl -ik --cert clientBob.crt --key clientBob.key "https://localhost:8443"
```

prod profile
```
$ curl -ik --cert clientBob.crt --key clientBob.key "https://yourdomain.com"
```

## TODO

- Certbot automatic renewal
- https://dzone.com/articles/spring-boot-secured-by-lets-encrypt Renewal Process

After renew certificate, export PEM to PKCS12 (for Spring Boot SSL)
```
openssl pkcs12 -export -in fullchain.pem -inkey privkey.pem -out keystore.p12 -name tomcat -CAfile chain.pem -caname root
```

## Reference links

- https://www.baeldung.com/x-509-authentication-in-spring-security
- https://pt.stackoverflow.com/questions/358172/%c3%89-poss%c3%advel-criar-um-certificado-pfx-e-definir-um-oid-para-alguns-par%c3%a2metros
- https://pt.stackoverflow.com/questions/80568/certificado-digital-com-php/195838#195838
- http://publicacao.certificadodigital.com.br/repositorio/pc/politica-a3.pdf
- https://certbot.eff.org/lets-encrypt/ubuntubionic-nginx