/**
 * @fileOverview Client to PBFT implementation: https://github.com/sydneyli/distributePKI
 */

/**
 * Creates an instance of the keyserver client.
 * @param {Object} config    PBFT cluster configuration
 */
export class PBFTClient {
  constructor(config) {
    this.nodes = config["nodes"];
    this.F = Math.ceil((this.nodes.length - 1) / 3);
  }

  /**
   * Get a verified public key either from the server by email address,
   * @param {string} email         email address to look up by
   */
  lookup(email) {
      return this._broadcast(this._path(email))
      .then(r => {
        console.log(`Looked Up: ${JSON.stringify(r)}`);
        return r;
      })
      .catch(e => {
        console.log(`Error: ${JSON.stringify(e)}`);
        throw e;
      });
  }

  /**
   * Upload a public key to the server. Lookup to verify committed.
   * @param {string} options.publicKeyArmored   The ascii armored key block
   * @param {string} options.email              user's email address
   * @yield {undefined}
   */
  upload(options) {
    // Workaround since PBFT server is just a KV store
    const payload = {
      keyId: "keyid",
      fingerprint: "fingerprint",
      userIds: [
        {name: "name", email: options.email, verified: true}],
      created: "2017-12-10T03: 03: 08.000Z",
      uploaded: "2017-12-10T03: 03: 20.763Z",
      algorithm: "rsa_encrypt_sign",
      keySize: 4096,
      publicKeyArmored: options.publicKeyArmored};

    return this._broadcast(this._path(options.email), "POST", JSON.stringify(payload))
      .then(r => {
        console.log(`Committed: ${JSON.stringify(r)}`);
        return r;
      })
      .catch(e => {
        console.log(`Error: ${JSON.stringify(e)}`);
        throw {message: e};
      });
  }

  /**
   * Broadcast to all nodes. Waits for F+1 successes with the same result or F+1 failures
   * with the same message before completing promise.
   * @param {string} path       The path to fetch
   * @param {string} method     HTTP method
   * @param {object} body       Optional body
   * @return {Promise}          Promise that resolves with response object containing status, statusText, and body
   */

  _broadcast(path, method, body) {
    const options = body ? {method, body} : {method: "GET"};
    const responseMap = new Proxy(new Map(), {get: (map, name) => name in map ? map[name] : 0});

    return new Promise((resolve, reject) => {
      var promiseResolved = false;
      const processResponse = (response) => {
        const status = response.status;
        const statusText = response.statusText;
          if (response.ok) {
              response.json().then(body => {
                  console.log(`Received Response ${status} ${statusText} ${body}`);
                  if ((responseMap[`${status}${statusText}${body}`] += 1) == this.F + 1 && !promiseResolved) {
                    promiseResolved = true;
                    resolve({status, statusText, body});
                  }});
          } else {
              console.log(`Received Failure ${status} ${statusText}`);
              var key = `${status}${statusText}`;
              responseMap[key] += 1;
              if (responseMap[key] == this.F + 1 && !promiseResolved) {
                promiseResolved = true;
                reject(`${status} ${statusText}`);
              }
          }
      };

      this.nodes
            .map(node => window.fetch(`http://${node["host"]}:${node["clientport"]}${path}`, options))
            .map(promise =>
                 Promise.race([
                   promise,
                   new Promise((_, reject) => window.setTimeout(() => {
                     reject({status: 520 , statusText: "Request Timeout"});
                   }, 7000))]))
            .forEach(promise => promise.then(processResponse).catch(processResponse));
    });
  }

  /**
   * Create a url with the proper query string for an
   * api request.
   * @param  {string} email         email address
   * @return {string}               The complete request url
   */
  _path(email) {
    if (email) {
      return `?name=${encodeURIComponent(email)}`;
    } else {
      console.log("email is empty");
      return null;
    }
  }
}
