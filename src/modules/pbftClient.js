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

        // Format this in a way that Mailvelope expects, with dummy fields for now
        const payload = {
          keyId: "keyid",
          fingerprint: "fingerprint",
          userIds: [
            {name: "name", email: email, verified: true}],
          created: "2017-12-10T03: 03: 20.763Z",
          uploaded: "2017-12-10T03: 03: 20.763Z",
          algorithm: "rsa_encrypt_sign",
          keySize: 4096,
          publicKeyArmored: r.body};
        return JSON.stringify(payload);
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
    const email = options.email;
    const publicKey = options.publicKeyArmored;
    
    // Lookup first to see if we need to ask for a signature
    return this.lookup(email)
      .then(() => this._broadcast("", "PUT", this.constructKeyPayload(email, publicKey))
            .then(r => {
              console.log(`Committed: ${JSON.stringify(r)}`);
              return r;
            })
            .catch(e => {
              console.log(`Error: ${JSON.stringify(e)}`);
              throw {message: e};
            }))
      .catch(e => {
        // Semi-hacky way to see if lookup returned with NOT FOUND
        if (e.startsWith(404)) {
          console.log(`The following is your public key: \n\n\n${publicKey}`);
          const signature = window.prompt(`This is a new email. Please acquire signature from domain authority and paste here. The public key can be copied from the console`);
          console.log(signature);
          return this._broadcast("", "POST", this.constructKeyPayload(email, publicKey))
            .then(r => {
              console.log(`Committed: ${JSON.stringify(r)}`);
              return r;
            })
            .catch(e => {
              console.log(`Error: ${JSON.stringify(e)}`);
              throw {message: e};
            });
        } else {
          throw e;
        }
      });
  }

  constructKeyPayload(email, publicKey) {
    return JSON.stringify({
      alias: email,
      key: publicKey,
      timestamp: Date.now()
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
      let promiseResolved = false;
      const processResponse = response => {
        const status = response.status;
        const statusText = response.statusText;
          if (response.ok) {
              response.json().then(body => {
                const res = `${status} ${statusText} ${body}`;
                console.log(`Received Response ${res}`);
                if ((responseMap[res] += 1) == this.F + 1 && !promiseResolved) {
                  promiseResolved = true;
                  resolve({status, statusText, body});
                } });
          } else {
            (response.text == undefined
             ? Promise.resolve("")
             : response.text())
              .then(body => {
              const error = `${status} ${statusText} ${body}`;
              console.log(`Received Failure ${error}`);
              responseMap[error] += 1;
              if (responseMap[error] == this.F + 1 && !promiseResolved) {
                promiseResolved = true;
                reject(error);
              }
            });
          }
      };

      this.nodes
            .map(node => window.fetch(`http://${node["host"]}:${node["clientport"]}${path}`, options))
            .map(promise =>
                 Promise.race([
                   promise,
                   new Promise((_, reject) => window.setTimeout(() => {
                     reject({status: 520, statusText: "Request Timeout"});
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
