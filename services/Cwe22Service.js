/* eslint-disable no-unused-vars */
const Service = require('./Service');
const cwe = require('../vulnlib/cwe22')

class Cwe22Service {

  /**
   * Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
   * vulnID00001
   *
   * vinput String Vulnerability ID 00001
   * returns String
   **/
  static cwe22vid00001({ vinput }) {
    return new Promise(
      async (resolve) => {
        try {
          let data = cwe.vulnID00001({ vinput })
          if (data instanceof Promise) {
            data = await data
          }
          resolve(Service.successResponse(data));
        } catch (e) {
          resolve(Service.rejectResponse(
            e.message || 'Invalid input',
            e.status || 405,
          ));
        }
      },
    );
  }

}

module.exports = Cwe22Service;
