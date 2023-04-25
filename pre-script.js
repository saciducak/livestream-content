// Following script is executed before every request in this collection. 

// Introduce delay in running the APIs only during collection/folder run.
// Delay wont be introduced if the APIs are running individually in postman app
if (pm.variables.get('delayed_run')) {
    setTimeout(() => {}, 1000); // in milliseconds
  }
  
  // This script obtains access_token by invoking PayPal OAuth 2 API and stores it in the collection variable with same name `access_token`. This token is then reused as an Bearer Token for each API invocation until. The script obtains a new access_token automatically when the original one is expired. When the client_id is changed, original access_token is discarded and replaced with new one obtained against that new client_id and client_secret pair.
  
  const auth_request = {
      url: pm.variables.get("base_url")+'/v1/oauth2/token',
      method: 'POST',
      header: {
          'content-type': 'application/x-www-form-urlencoded',
          'authorization': 'Basic ' + btoa(pm.variables.get("client_id") + ':' +
              pm.variables.get("client_secret"))
      },
      body: {
          mode: 'urlencoded',
          urlencoded: [{
              key: 'grant_type',
              value: 'client_credentials'
          }]
      }
  };
  
  //console.info('Invoking: ', pm.info.requestName, pm.info.requestId);
  if(pm.request.url.path.join('/').includes('/oauth2/token')) {
      // excude token generation API from reusing the token.
      return;
  }
  var needNewToken = true;
  if (!pm.collectionVariables.get('access_token_expiry') ||
      !pm.collectionVariables.get('access_token') ||
      !pm.collectionVariables.get('access_token_for')) {
      console.log('access_token or its expiry date are missing.');
  } else if (pm.collectionVariables.get('access_token_expiry') <= (new Date()).getTime()) {
      console.log('access_token is expired')
  } else if (pm.collectionVariables.get('access_token_for') != pm.variables.get("client_id")) {
      console.log('client_id is changed', 
          pm.collectionVariables.get('access_token_for'), 
          pm.variables.get("client_id"))
  } else {
      //console.log('Reusing previous access_token, valid until ', new Date(pm.collectionVariables.get('access_token_expiry')));
      needNewToken = false;
  }
  
  if (needNewToken === true) {
  
      // clear cached token before obtaining a new one
      pm.collectionVariables.unset('access_token');
      pm.collectionVariables.unset('access_token_expiry');
      pm.collectionVariables.unset('access_token_for');
  
      pm.sendRequest(auth_request, function(err, response) {
          if (response.code === 200) {
              console.log('Saving the access_token')
              var responseJson = response.json();
              pm.collectionVariables.set('access_token', responseJson.access_token)
  
              var expiryDate = new Date();
              expiryDate.setSeconds(expiryDate.getSeconds() + responseJson.expires_in);
              //console.log('Saving the access_token_expiry', expiryDate.getTime());
              pm.collectionVariables.set('access_token_expiry', expiryDate.getTime());
              //console.log('Saving the access_token_for');
              pm.collectionVariables.set('access_token_for', pm.variables.get("client_id"));
  
          } else {
              console.error("Failed to obtain access_token", err, response.code, response.headers.get('Paypal-Debug-Id'), response.json());
          }
      });
  }
  
  // global function to detect if APIs are being invoked against sandbox
  Object.prototype.isSandbox = function() {
      return pm.variables.get("base_url").includes("sandbox.paypal.com");
  }
  
  // global function to get tomorrow's date in ISO8601 format e.g. 2023-01-26T19:58:16.351Z
  Object.prototype.getTomorrow = function() {
      const tomorrow = new Date();
      tomorrow.setDate(tomorrow.getDate() + 1)
      return tomorrow.toISOString();
  }
  
  // get value for PayPal-Auth-Assertion header while acting on behalf of a consented seller
  // Typical Usage: pm.collectionVariables.set('PayPal-Auth-Assertion', getAuthAssertionFor(pm.variables.get('seller1_payer_id')));
  Object.prototype.getAuthAssertionFor = function(sellerEmailORPayerId) {
      var data = {
          "payer_id": sellerEmailORPayerId
      };
      return getJWT(pm.variables.get('client_id'), data, "none");
      //return getJWT(pm.variables.get('client_id'), data, "HS256", pm.variables.get('client_secret'));
  }
  
  // generate JSON Web Tokens (JWT) by encoding the header and payload with base64url, 
  // and optionally signing the token with a secret
  Object.prototype.getJWT = function(iss, data, alg, secret) {
      const header = { alg };
      const encodedHeader = base64url(JSON.stringify(header));
      const payload = { ...{ iss }, ...data };
      const encodedPayload = base64url(JSON.stringify(payload));
      const token = `${encodedHeader}.${encodedPayload}`;
      const signature = alg && alg !== 'none'
          ? base64url(CryptoJS.HmacSHA256(token, secret || '').toString())
          : '';
      return `${token}.${signature}`;
  }
  
  Object.prototype.base64url = function(source) {
      return btoa(source)
          .replace(/=+$/, '')
          .replace(/\+/g, '-')
          .replace(/\//g, '_');
  }
  