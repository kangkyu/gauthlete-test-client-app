# gauthlete-test-client-app

test app for [Gauthlete](https://github.com/kangkyu/gauthlete) library development

```
CLIENT_ID='...' \
CLIENT_SECRET='...' \
go run .
```

For this app, make client id and secret! There's no endpoint fot that yet (on the authorization server side), but for now we can still make request to these endpoint to get client id and secret:

https://docs.authlete.com/en/shared/latest#get-/api/client/get/list

https://docs.authlete.com/en/shared/latest#post-/api/client/update/-clientId-
