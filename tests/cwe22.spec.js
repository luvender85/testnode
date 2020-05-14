const {
    describe, before, after, it,
  } = require('mocha');
  const chai = require('chai');
  const chaiAsPromised = require('chai-as-promised');
  const { get } = require('axios');
  
  const logger = require('./logger');
  const config = require('./config');
  const ExpressServer = require('../expressServer');

  const cwe22 = require('../vulnlib/cwe22/index.js');
  
  const app = new ExpressServer(config.URL_PORT, config.OPENAPI_YAML);
  chai.use(chaiAsPromised);
  chai.should();
  
  describe('Test cwe22', () => {
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
  

    it('should call cwe22.vulnID00001 directly', async () => {
      const result = cwe22.vulnID00001({"vinput": '../../../../../../../../../../../../etc/passwd'})
      result.should.include('nobody', 'Expecting this response')
    });

    it('should call the vulnID00001 endpoint', async () => {
      const indexResponse = await get(`${config.URL_PATH}:${config.URL_PORT}/v1/cwe/22/00001?vinput=../../../../../../../../../../../../etc/passwd`);
      indexResponse.data.should.include('nobody', 'Expecting nobody in body response');
    });

});