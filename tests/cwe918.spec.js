const {
    describe, before, after, it,
  } = require('mocha');
  const chai = require('chai');
  const chaiAsPromised = require('chai-as-promised');
  const { get } = require('axios');
  
  const logger = require('./logger');
  const config = require('./config');
  const ExpressServer = require('../expressServer');

  const cwe918 = require('../vulnlib/cwe918/index.js');
  
  const app = new ExpressServer(config.URL_PORT, config.OPENAPI_YAML);
  chai.use(chaiAsPromised);
  chai.should();
  
  describe('Test cwe918', () => {
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
  

    it('should call cwe918.vulnID00001 directly', async () => {
      const result = await cwe918.vulnID00001({"vinput": `${config.URL_PATH}:${config.URL_PORT}/`})
      result.should.include('Hello World', 'Expecting this response')
    });

    it('should call the vulnID00001 endpoint', async () => {
      const indexResponse = await get(`${config.URL_PATH}:${config.URL_PORT}/v1/cwe/918/00001?vinput=${config.URL_PATH}:${config.URL_PORT}/`);
      indexResponse.data.should.include('Hello World', 'Expecting Hello World in body response');
    });

    it('should call cwe918.vulnID00002 directly', async () => {
      const result = await cwe918.vulnID00002({"vinput": `://localhost:${config.URL_PORT}`})
      result.should.include('Hello World', 'Expecting this response')
    });

    it('should call the vulnID00002 endpoint', async () => {
      const indexResponse = await get(`${config.URL_PATH}:${config.URL_PORT}/v1/cwe/918/00002?vinput=://localhost:${config.URL_PORT}`);
      indexResponse.data.should.include('Hello World', 'Expecting Hello World in body response');
    });

});