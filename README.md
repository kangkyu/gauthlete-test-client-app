# gauthlete-test-client-app

test app for [Gauthlete](https://github.com/kangkyu/gauthlete) library development

```
AUTHLETE_CLIENT_ID='...' \
AUTHLETE_CLIENT_SECRET='...' \
go run .
```

For this app, make client id and secret! There's no endpoint fot that yet (on the [gauthlete-test-application](https://github.com/kangkyu/gauthlete-test-application) side), but for now we can still make request to these endpoint to get client id and secret:

https://docs.authlete.com/en/shared/latest#get-/api/client/get/list

https://docs.authlete.com/en/shared/latest#post-/api/client/create
https://docs.authlete.com/en/shared/latest#post-/api/client/update/-clientId-
