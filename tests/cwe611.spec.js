const {
    describe, before, after, it,
  } = require('mocha');
  const chai = require('chai');
  const chaiAsPromised = require('chai-as-promised');
  const axios = require('axios');
  
  const logger = require('./logger');
  const config = require('./config');
  const ExpressServer = require('../expressServer');
  const querystring = require('querystring');

  const cwe611 = require('../vulnlib/cwe611/index.js');
  
  const app = new ExpressServer(config.URL_PORT, config.OPENAPI_YAML);
  chai.use(chaiAsPromised);
  chai.should();
  
  describe('Test cwe611', () => {
    before(async () => {
      try {
        await app.launch();
        logger.info('express server launched\n');
      } catch (error) {
        logger.info(error);
        await app.close();
        throw (error);
      }
    });
  
    after(async () => {
      await app.close()
        .catch(error => logger.error(error));
      logger.error('express server closed');
    });
  

    it('should call cwe611.vulnID00001 directly', async () => {
      const result = cwe611.vulnID00001({vinput: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>"});
      result.should.include('nobody', 'Expecting this response')
    });

    it('should call the cwe611.vulnID00001 endpoint', async () => {
      let url = `${config.URL_PATH}:${config.URL_PORT}/v1/cwe/611/00001`;
      const options = {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        data: querystring.stringify({vinput: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>"}),
        url
      };
      const indexResponse = await axios(options);
      indexResponse.data.should.include('nobody', 'Expecting a way to determine vulnerability');
    });

});