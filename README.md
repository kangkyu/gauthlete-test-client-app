# gauthlete-test-client-app

test app for [Gauthlete](https://github.com/kangkyu/gauthlete) library development

```
AUTH_SERVER_CLIENT_ID='...' \
AUTH_SERVER_CLIENT_SECRET='...' \
go run .
```

For this app, make client id and secret! There's no endpoint for that yet (on the [gauthlete-test-application](https://github.com/kangkyu/gauthlete-test-application) side),
but for now we can still make requests to these endpoints to get client id and secret:

https://docs.authlete.com/en/shared/2.3.0#get-/api/client/get/list

https://docs.authlete.com/en/shared/2.3.0#post-/api/client/create
https://docs.authlete.com/en/shared/2.3.0#post-/api/client/update/-clientId-
