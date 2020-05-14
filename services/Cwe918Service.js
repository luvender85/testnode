/* eslint-disable no-unused-vars */
const Service = require('./Service');
const cwe = require('../vulnlib/cwe918')

class Cwe918Service {

  /**
   * Server-Side Request Forgery (SSRF)
   * vulnID00001
   *
   * vinput String Vulnerability ID 00001
   * returns String
   **/
  static cwe918vid00001({ vinput }) {
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

  /**
   * Server-Side Request Forgery (SSRF)
   * vulnID00002
   *
   * vinput String Vulnerability ID 00002
   * returns String
   **/
  static cwe918vid00002({ vinput }) {
    return new Promise(
      async (resolve) => {
        try {
          let data = cwe.vulnID00002({ vinput })
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

module.exports = Cwe918Service;
