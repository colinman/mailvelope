/**
 * Copyright (C) 2016-2017 Mailvelope GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

import {prefs} from './prefs';
import {PBFTClient} from './pbftClient.js';

/**
 * @fileOverview A simple wrapper backed by PBFTClient
 */

/**
 * Creates an instance of the keyserver.
 * @param {String} baseUrl    (optional) The server's base url
 */
export default class KeyServer {
  getPBFTClient() {
    if (this._pbftClient) {
      return Promise.resolve(this._pbftClient);
    } else {
      return window.fetch(chrome.runtime.getURL("config/cluster.json"))
        .then(response => response.json())
        .then(response => new PBFTClient(response));
    }
  }

  /**
   * Check the user's preferences if TOFU/auto-lookup is enabled.
   * @return {boolean}   If TOFU is enabled or not
   */
  getTOFUPreference() {
    return prefs.keyserver.mvelo_tofu_lookup === true;
  }

  /**
   * Get a verified public key either from the server by either email address,
   * key id, or fingerprint.
   * @param {string} options.email         (optional) The user id's email address
   * @param {string} options.keyId         (optional) The long 16 char key id
   * @param {string} options.fingerprint   (optional) The 40 char v4 fingerprint
   * @yield {Object}                       The public key object
   */
  lookup(options) {
    console.log(`Lookup ${JSON.stringify(options)}`);
    if (!options.email) {
      return Promise.reject("Only lookup by email is currently supported by PBFT");
    }

    return this.getPBFTClient()
      .then(client => client.lookup(options.email))
      .then(response => JSON.parse(response.body))
      .catch(error => console.log(error));
  }

  /**
   * Upload a public key to the server for verification by the user. Normally
   * a verification mail is sent out to all of the key's user ids, unless a primary
   * email attribute is supplied. In which case only one email is sent.
   * @param {string} options.publicKeyArmored   The ascii armored key block
   * @param {string} options.primaryEmail       (optional) user's primary email address
   * @yield {undefined}
   */
  upload(options) {
    console.log(`Upload ${JSON.stringify(options)}`);
    const payload = {publicKeyArmored: options.publicKeyArmored};
    if (options.primaryEmail) {
      payload.primaryEmail = options.primaryEmail;
    }
    return this.getPBFTClient()
          .then(client => client.upload(options));
  }

  /**
   * Request deletion of a user's key from the keyserver. Either an email address or
   * the key id have to be specified. The user will receive a verification email
   * after the request to confirm deletion.
   * @param {string} options.email   (optional) The user id's email address
   * @param {string} options.keyId   (optional) The long 16 char key id
   * @yield {undefined}
   */
  remove(options) {
    return window.fetch(this._url(options), {
      method: 'DELETE'
    })
    .then(this._checkStatus);
  }

  /**
   * Helper function to create a url with the proper query string for an
   * api request.
   * @param  {string} options.email         (optional) The user id's email address
   * @param  {string} options.keyId         (optional) The long 16 char key id
   * @param  {string} options.fingerprint   (optional) The 40 char v4 fingerprint
   * @return {string}                       The complete request url
   */
  _url(options) {
    let url = `${this._baseUrl}/api/v1/key`;
    if (options && options.email) {
      url += `?email=${encodeURIComponent(options.email)}`;
    } else if (options && options.fingerprint) {
      url += `?fingerprint=${encodeURIComponent(options.fingerprint)}`;
    } else if (options && options.keyId) {
      url += `?keyId=${encodeURIComponent(options.keyId)}`;
    }
    return url;
  }

  /**
   * Helper function to deal with the HTTP response status
   * @param  {Object} response   The fetch api's response object
   * @return {Object|Error}      Either the response object in case of a successful
   *                             request or an Error containing the statusText
   */
  _checkStatus(response) {
    if (response.status >= 200 && response.status < 300) {
      return response;
    } else {
      const error = new Error(response.statusText);
      error.response = response;
      throw error;
    }
  }
}
