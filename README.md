# FastAPI - JWT with python-jose, access & refresh token + pubkey example

There wasn't a simple and complete example, so I've made my own.

## Generate Keys

```bash
ssh-keygen -t rsa -b 4096 -m PEM -f tmp/priv.key && rm tmp/priv.key.pub
ssh-keygen -f tmp/priv.key -e -m pkcs8 > tmp/pub.key
```
