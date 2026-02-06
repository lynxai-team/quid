## Javascript client

[![pub package](https://img.shields.io/npm/v/quidjs)](https://www.npmjs.com/package/quidjs)

Install the [QuidJS library](https://github.com/TealsFi/quidjs).
It transparently manage the requests to API servers.
If a server returns a 401 Unauthorized response
when an access token is expired,
the client library will request a new access token from a Quid server,
using a refresh token, and will retry the request with the new access token

```bash
yarn add quidjs
# or
npm install quidjs
```

## Usage

```typescript
import { useQuidRequests } from "quidjs";

const quid = useQuidRequests({
  namespace: "my_namespace",
  timeouts: {
    accessToken: "5m",
    refreshToken: "24h"
  },
  quidUri: "https://localhost:8082", // quid server url
  serverUri: "https://localhost:8000", // url of your backend
  verbose: true,
});

// login the user
await quid.login("user", "pwd");

// use the quid instance to request json from the backend
// GET request
const response: Record<string,any> = await quid.get<Record<string,any>>("/api/get");
console.log("Backend GET response:", response)
// POST request
const payload = {"foo": "bar"};
const response2: Record<string,any> = await quid.post<Record<string,any>>("/api/post", payload);
console.log("Backend POST response:", response2)
```

## Examples

- [Script src](https://github.com/teal-finance/quidjs/tree/master/examples/umd)
- [Script module](https://github.com/teal-finance/quidjs/tree/master/examples/esm)
