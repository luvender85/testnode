/* eslint-disable no-unused-vars */
const Service = require('./Service');
const cwe = require('../vulnlib/cwe78')

class Cwe78Service {

  /**
   * INSERT CWE CATEGORY TYPE HERE (e.g. SSRF)
   * vulnID00001
   *
   * vinput String Vulnerability ID 00001
   * returns String
   **/
  static cwe78vid00001({ vinput }) {
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

module.exports = Cwe78Service;
